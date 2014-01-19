-- These functions and triggers make it so that each aname that has an entry in power DNS also autogenerates a PTR record for it
-- It handles resolving dependencies, generally favoring the most recently updated entry as the primary entry

CREATE OR REPLACE FUNCTION getptrzone(IN text) RETURNS text AS
$$
declare
  octets text[];
begin
  octets := regexp_split_to_array($1, E'\\.');
  return octets[3] || '.' || octets[2] || '.' || octets[1] || '.in-addr.arpa';
end
$$ LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION getptrname(IN text) RETURNS text AS
$$
declare
  octets text[];
begin
  octets := regexp_split_to_array($1, E'\\.');
  return octets[4] || '.' || octets[3] || '.' || octets[2] || '.' || octets[1] || '.in-addr.arpa';
end
$$ LANGUAGE 'plpgsql';

create or replace function havezone(in text) returns boolean as
$$
begin
	return case when count(id) >= 1 then true else false end from domains where name = $1;
end
$$ language 'plpgsql';

create or replace function haveptr(in text) returns boolean as
$$
begin
	return case when count(id) >= 1 then true else false end from records where name = $1 and type = 'PTR';
end
$$ language 'plpgsql';


-- Insert stuff! 
-- 1) New aname's content ex: 44.24.245.1   2) New aname's name ex: b.ns.hamwan.net
create or replace function insertptr(in text, in text) returns integer as
$$
declare
	domain_id_i integer;
begin
	select into domain_id_i id from domains where name = getptrzone($1);
	insert into records (domain_id, name, type, content, auth) values (domain_id_i, getptrname($1), 'PTR', $2, true);
	return lastval();
end
$$ language 'plpgsql';


create or replace function insertptr_trigger() returns trigger as
$$
declare
	ptrzone text;
begin
	select into ptrzone getptrzone(NEW.content);
	if havezone(ptrzone)
	then
		-- Find out if theres already a PTR record for that IP address
		if (select count(*) from records WHERE name = getptrname(NEW.content) AND type = 'PTR') < 1 then
			-- No there isn't, so lets add a new one
			PERFORM insertptr(NEW.content, NEW.name);
		else
			-- There is an existing PTR, so lets just update it with the new proper aname reference
			PERFORM updateptr(NEW.content, NEW.name, NEW.content);
		end if;
	end if;
	return NEW;
end
$$ language 'plpgsql';



-- Update stuff! 

-- vars are: 1) New aname's content ex: 44.24.245.1   2) New aname's name ex: b.ns.hamwan.net   3) Old aname's content ex: 44.24.245.2
create or replace function updateptr(in text, in text, in text) returns integer as
$$
declare
	domain_id_i integer;
	return_id integer;
begin
	select into domain_id_i id from domains where name = getptrzone($1);
		
	UPDATE records SET (domain_id, name, "type", content, auth) = (domain_id_i, getptrname($1), 'PTR', $2, true) WHERE name = getptrname($3) RETURNING id INTO return_id;
	
	-- Find out if there are multiple A names to this single PTR, because if there are, and we changed the IP address on the PTR, we need to create the missing PTR record for the old IP
	if (select count(*) from records WHERE type = 'A' AND content = $3) > 0 AND $1 <> $3 then
		-- Ok, there are multiple A records for this same IP, and we're changing the IP, so we need to add a PTR for the old IP.
		PERFORM insertptr($3, (select name from records where type = 'A' AND content = $3 limit 1));
	end if;

	RETURN return_id;
end
$$ language 'plpgsql';


create or replace function updateptr_trigger() returns trigger as
$$
declare
	ptrzone text;
	retval integer := 0;
begin
	select into ptrzone getptrzone(NEW.content);
	if havezone(ptrzone)
	then
		select into retval updateptr(NEW.content, NEW.name, OLD.content);
		-- Lets handle if someone edited an aname and made it point to an IP that already has a PTR
		if (select count(*) from records WHERE type = 'PTR' AND name = getptrname(NEW.content)) > 1 then
			-- Ok, so we now know there are multiple ptrs for 1 IP. Lets delete the old ones and keep the new one that we just added
			-- First, lets delete PTR records with the same IP as our new one but different content
			DELETE from records WHERE name = getptrname(NEW.content) AND type = 'PTR' AND content <> NEW.name AND auth = true;
			-- Then, just in case someone goofed up and made an exact duplicate of an existing Aname, lets get rid of all PTR records with the same IP and the same content EXCEPT the oldest one
			DELETE FROM records WHERE type = 'PTR' AND name = getptrname(NEW.content) AND content = NEW.name AND ctid NOT IN 
				(SELECT ctid FROM records WHERE type = 'PTR' AND name = getptrname(NEW.content) AND content = NEW.name ORDER BY id ASC LIMIT 1);
			
		end if;
		
	end if;
	return NEW;
end
$$ language 'plpgsql';


CREATE TRIGGER a_ptr_update AFTER UPDATE ON records FOR EACH ROW WHEN (((OLD.type)::text = 'A'::text)) EXECUTE PROCEDURE updateptr_trigger();



-- Delete stuff!

-- 1) aname's content ex: 44.24.245.1   2) aname's name ex: b.ns.hamwan.net
create or replace function deleteptr(in text, in text) returns integer as
$$
declare
	domain_id_i integer;
	return_id integer;
begin
	select into domain_id_i id from domains where name = getptrzone($1);
	DELETE FROM records WHERE domain_id = domain_id_i AND name = getptrname($1) AND type = 'PTR' AND content = $2 AND auth = true RETURNING id INTO return_id;
	return return_id;
end
$$ language 'plpgsql';


create or replace function deleteptr_trigger() returns trigger as
$$
declare
	ptrzone text;
	retval integer := 0;
begin
	select into ptrzone getptrzone(OLD.content);
	if havezone(ptrzone)
	then
		-- Find out if there are multiple a names for the same IP, because if that's the case we dont want to actually delete the ptr but instead just update it to match one of the remaining A names
		if (SELECT COUNT(*) FROM records WHERE type = 'A' AND content = OLD.content) > 0 then
			-- there is at least one remaining a name with that IP address, so lets update the ptr to point to the newest one
			select into retval updateptr(OLD.content, (SELECT name FROM records WHERE type = 'A' AND content = OLD.content ORDER BY id DESC LIMIT 1), OLD.content);
		else
			-- Ok, there aren't any remaining a names for that IP, so let's delete the ptr altogether
			select into retval deleteptr(OLD.content, OLD.name);
		end if;
	end if;
	return OLD;
end
$$ language 'plpgsql';


CREATE TRIGGER a_ptr_delete AFTER DELETE ON records FOR EACH ROW WHEN (((OLD.type)::text = 'A'::text)) EXECUTE PROCEDURE deleteptr_trigger();