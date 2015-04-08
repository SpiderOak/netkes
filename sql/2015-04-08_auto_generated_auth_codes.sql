begin;

alter table admin_setup_tokens add column auto_generated boolean default False;

drop view admin_setup_tokens_use;

create or replace view admin_setup_tokens_use as 
    select token, date_created, expiry, no_devices_only, 
        single_use_only, auto_generated,
        exists(select * from admin_token_avatar_use au where au.token=a.token) as used,
        case 
            when single_use_only and exists(select * from admin_token_avatar_use au where au.token=a.token) then false
            when expiry < now() then false
            else true 
        end as active
    from admin_setup_tokens a;

grant select on admin_setup_tokens_use to admin_console;

commit;
