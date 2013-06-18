BEGIN;

CREATE USER directory_agent WITH PASSWORD 'initial';
CREATE USER admin_console WITH PASSWORD 'iexyjtso';

CREATE TABLE passwords (
  email varchar(64) primary key,
  pw_hash varchar(128)
);
GRANT SELECT, UPDATE, INSERT, DELETE ON passwords TO directory_agent;

CREATE TABLE users (
       uniqueid text primary key,
       email varchar(64) unique not null,
       avatar_id int4 unique not null,
       givenname varchar(64) not null,
       surname varchar(64) not null,
       group_id int4 not null,
       enabled boolean not null default true
);
GRANT SELECT, UPDATE, INSERT, DELETE ON users TO directory_agent;

CREATE INDEX users_idx ON users (uniqueid, email, avatar_id);

CREATE LANGUAGE plpgsql;

-- the following is from:
-- http://www.postgresql.org/docs/current/static/plpgsql-control-structures.html#PLPGSQL-UPSERT-EXAMPLE
CREATE FUNCTION upsert_password(user_email VARCHAR(64), pw VARCHAR(128)) RETURNS VOID AS
$$
BEGIN
        LOOP
                UPDATE passwords SET pw_hash = pw WHERE user_email = email;
                IF found THEN
                   RETURN;
                END IF;

                -- If we didn't update any rows, try now to insert a row.
                BEGIN
                        INSERT INTO passwords VALUES (user_email, pw);
                        RETURN;
                EXCEPTION WHEN unique_violation THEN
                        -- do nothing, and try to loop over again to update.
                END;
        END LOOP;
END;
$$
LANGUAGE plpgsql;

COMMIT;
