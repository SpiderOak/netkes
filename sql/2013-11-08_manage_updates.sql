begin;

create table updates (
    name varchar(100) primary key,
    update_time timestamp not null default now()
);

grant select, insert on updates to directory_agent;

commit;
