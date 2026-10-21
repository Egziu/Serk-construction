#!/usr/bin/env bash
# Re-runs the audit's raw-SQL attacks against the remediated schema, as a
# tenant's own database role (the role a compromised application holds).
set -u
DB=${DB:-serk_gate_a}
SU="psql -h /tmp -p 5433 -U postgres -d $DB -X -At"
echo "### Gate A after-evidence — $(psql -h /tmp -p 5433 -U postgres -d $DB -Atc 'select version()' | cut -d, -f1), $(date -u +%FT%TZ)"
echo "### schema migrations applied: $($SU -c "select string_agg(version::text, ',' order by version) from schema_migrations" 2>/dev/null || $SU -c "select 'n/a'")"
# Tenant A: has a POSTED and a DRAFT journal in the same entity.
A=$($SU -c "select p.tenant_id from journals p join journals d on d.tenant_id=p.tenant_id and d.legal_entity_id=p.legal_entity_id and d.status='DRAFT'
            where p.status='POSTED' and exists(select 1 from journal_lines l where l.journal_id=p.id and l.line_no=2) limit 1")
B=$($SU -c "select id from tenants where id <> '$A' limit 1")
W=$($SU -c "select d.tenant_id from workflow_definitions d join journals j on j.tenant_id=d.tenant_id and j.status='DRAFT'
            where d.status='PUBLISHED' and d.mandatory and d.subject='journal' limit 1")
PW=evidence-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
role(){ echo "serk_t_$(echo $1 | tr -d -)"; }
for T in $A $W; do
  R=$(role $T)
  $SU -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1
  $SU -c "CREATE ROLE $R LOGIN INHERIT NOSUPERUSER NOBYPASSRLS PASSWORD '$PW' IN ROLE serk_app" >/dev/null
done
as(){ PGPASSWORD=$PW psql -h /tmp -p 5433 -U $(role $1) -d $DB -X -v ON_ERROR_STOP=0 "${@:2}" 2>&1; }

echo; echo "### SC-04 after: tenant A's own role tries to switch to tenant B"
as $A -c "select session_user, current_tenant() = '$A'::uuid as bound_to_A" \
      -c "select set_config('app.tenant_id', '$B', false) is not null as gu_set" \
      -c "select count(*) as b_journals_visible from journals where tenant_id = '$B'" \
      -c "select count(*) as tenants_visible from tenants"

P=$($SU -c "select id from journals where tenant_id='$A' and status='POSTED' and exists(select 1 from journal_lines l where l.journal_id=journals.id and l.line_no=2) limit 1")
D=$($SU -c "select d.id from journals d join journals p on p.id='$P' where d.tenant_id='$A' and d.status='DRAFT' and d.legal_entity_id=p.legal_entity_id limit 1")
echo; echo "### SC-01 after: move line 2 of a POSTED journal into a DRAFT journal (tenant role, then schema owner)"
as $A -c "update journal_lines set journal_id='$D' where journal_id='$P' and line_no=2"
echo "-- as superuser/schema owner:"
psql -h /tmp -p 5433 -U postgres -d $DB -X -c "update journal_lines set journal_id='$D' where journal_id='$P' and line_no=2" 2>&1
echo "-- posted journal still balanced:"
$SU -c "select status, sum(amount) filter (where side='DEBIT') dr, sum(amount) filter (where side='CREDIT') cr from journal_lines l join journals j on j.id=l.journal_id where j.id='$P' group by status"

echo; echo "### SC-14 after: sub-minor-unit ETB amount on a DRAFT journal line (tenant role)"
COLS=$($SU -c "select string_agg(column_name, ',' order by ordinal_position) from information_schema.columns where table_name='journal_lines' and column_name not in ('line_no','amount')")
as $A -c "insert into journal_lines($COLS,line_no,amount) select $COLS, 99, 100.0049 from journal_lines where journal_id='$D' and line_no=1"

J=$($SU -c "select id from journals where tenant_id='$W' and status='DRAFT' limit 1")
echo; echo "### Workflow after: approve a DRAFT journal directly while a mandatory workflow is published (tenant role)"
as $W -c "update journals set status='APPROVED', approved_by='u-attacker', approved_at=now() where id='$J'"
echo "-- forge an effect row without decisions:"
I=$($SU -c "select id from workflow_instances where tenant_id='$W' and status='ACTIVE' limit 1")
if [ -n "$I" ]; then
  as $W -c "insert into workflow_effects(tenant_id,instance_id,step_index,action,subject_type,subject_id,executed_by) select tenant_id,id,current_step,'journal.approve',subject_type,subject_id,'u-attacker' from workflow_instances where id='$I'"
else echo "(no ACTIVE instance left in this tenant)"; fi

echo "-- start an instance of the mandatory definition with a one-person route:"
DEF=$($SU -c "select id from workflow_definitions where tenant_id='$W' and status='PUBLISHED' and mandatory and subject='journal'")
as $W -c "insert into workflow_instances(tenant_id,definition_id,subject_type,subject_id,facts,route,initiated_by)
          values ('$W','$DEF','journal','$J','{\"created_by\":\"x\"}','[{\"id\":\"a\",\"permission\":\"journal.approve\",\"approvals\":1,\"effect\":\"journal.approve\"}]','mallory')"
echo "-- retire the mandatory definition directly:"
as $W -c "update workflow_definitions set status='RETIRED' where id='$DEF'"

for T in $A $W; do $SU -c "DROP ROLE IF EXISTS $(role $T)" >/dev/null; done
