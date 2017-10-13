begin;

alter table passwords alter column email type varchar(150);
alter table passwords owner to admin_console;

alter table users alter column email type varchar(150);

commit;
