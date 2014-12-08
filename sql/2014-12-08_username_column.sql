begin;

alter table users add column username varchar(64) unique;

commit;
