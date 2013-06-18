begin;

create table admin_setup_tokens (
    token varchar(40) primary key,
    date_created timestamp not null default current_timestamp,
    expiry timestamp not null default current_timestamp + '3 days'::interval,
    no_devices_only bool not null default TRUE,
    single_use_only bool not null default TRUE
);

create table admin_token_avatar_use (
    token varchar(40) not null references admin_setup_tokens,
    avatar_id int4 not null references users (avatar_id),
    timestamp timestamp not null default current_timestamp
);

create or replace view admin_setup_tokens_use as 
    select token, date_created, expiry, no_devices_only, single_use_only,
        exists(select * from admin_token_avatar_use au where au.token=a.token) as used,
        case 
            when single_use_only and exists(select * from admin_token_avatar_use au where au.token=a.token) then false
            when expiry < now() then false
            else true 
        end as active
    from admin_setup_tokens a;

grant select on admin_setup_tokens_use to admin_console;
grant select, insert, update on admin_setup_tokens to admin_console;
grant select, update on admin_setup_tokens to directory_agent;
grant select, insert on admin_token_avatar_use to directory_agent;

commit;
