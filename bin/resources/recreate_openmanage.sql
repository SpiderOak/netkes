SELECT
    pg_terminate_backend (pg_stat_activity.procpid)
FROM
    pg_stat_activity
WHERE
    pg_stat_activity.datname = 'openmanage'
    and procpid != pg_backend_pid()
;
drop database openmanage;
create database openmanage;
