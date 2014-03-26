begin;

create table sql_updates (
    name varchar(100) primary key,
    update_time timestamp not null default now()
);

grant select, insert on sql_updates to directory_agent;

insert into sql_updates (name) values ('base_schema.sql');
insert into sql_updates (name) values ('2012-12-11_blue_1_2.sql');
insert into sql_updates (name) values ('2013-04-02_manage_sql_updates.sql');
insert into sql_updates (name) values ('2014-02-01_admin_groups.sql');

commit;

/*
create function execute_once(name varchar, sql text) returns boolean as $$
declare executed boolean;
begin
    execute 'select true from sql_updates where name=$1' 
    into executed using name;
    if coalesce(executed, false) != true then
        execute sql;
        execute 'insert into sql_updates (name) values ('
            || quote_literal(name)
            || ')';
        return true;
    else
        return false;
    end if;
end;
$$ language plpgsql;

commit;
*/
