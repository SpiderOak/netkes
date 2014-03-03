begin;

alter table admin_token_avatar_use drop constraint admin_token_avatar_use_avatar_id_fkey;

commit;
