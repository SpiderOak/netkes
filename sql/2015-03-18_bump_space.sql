begin;

CREATE TABLE "bumped_user" (
    "id" serial NOT NULL PRIMARY KEY,
    "email" varchar(75) NOT NULL,
    "bonus_gb_reset" boolean NOT NULL,
    "time_to_reset_bonus_gb" timestamp with time zone NOT NULL
);

grant all on bumped_user to admin_console;
grant all on bumped_user_id_seq to admin_console;

commit;
