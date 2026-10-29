/*
# Fix "Database error saving new user" — function search_path + trigger fix

## Problem
The `handle_new_user()` SECURITY DEFINER trigger function (which auto-creates a profile row
when a new auth user signs up) had no fixed `search_path`. In Supabase, a mutable search_path
on a SECURITY DEFINER function can cause "Database error saving new user" during `auth.signUp()`
because the function may fail to resolve the `profiles` table in its schema.

Additionally, all SECURITY DEFINER functions in the schema lacked a fixed search_path,
which is flagged by the database linter as a security risk.

## Changes

### 1. Fixed search_path on all SECURITY DEFINER functions
- `handle_new_user()` — the trigger function on auth.users
- `submit_join_request()` — join request RPC
- `get_own_join_request_status()` — join request status RPC

### 2. Fixed search_path on SECURITY INVOKER helper functions
- `is_inst_member()` — institution membership check
- `can_access_class()` — class access check
- `calc_lesson_duration()` — lesson duration trigger

### 3. Revoked EXECUTE from anon on handle_new_user
- `handle_new_user()` is a trigger function, never called directly by clients.
  Revoked EXECUTE from `anon` and `PUBLIC` to close the security gap.

### 4. Recreated the auth trigger
- Dropped and recreated `on_auth_user_created` to ensure it points to the updated function.

### Security
- No new tables, columns, or policies.
- All functions now have `SET search_path = ''` (empty = schema-only, safest in Supabase)
  which forces them to use only the `public` schema where all tables live.
- `handle_new_user` EXECUTE revoked from anon/PUBLIC, granted only to authenticated
  (though it's only called via trigger, not directly).
*/

-- 1. Recreate handle_new_user with fixed search_path
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  INSERT INTO public.profiles (user_id, email, full_name)
  VALUES (NEW.id, NEW.email, '')
  ON CONFLICT (user_id) DO NOTHING;
  RETURN NEW;
END;
$$;

-- Revoke EXECUTE from anon/PUBLIC (trigger functions don't need direct call access)
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.handle_new_user() TO authenticated;

-- 2. Recreate submit_join_request with fixed search_path
CREATE OR REPLACE FUNCTION public.submit_join_request(p_institution_code text, p_email text, p_full_name text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_inst public.institutions%ROWTYPE;
  v_existing public.join_requests%ROWTYPE;
BEGIN
  SELECT * INTO v_inst FROM public.institutions WHERE joining_code = p_institution_code;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'invalid_code');
  END IF;
  IF v_inst.code_revoked_at IS NOT NULL THEN
    RETURN jsonb_build_object('error', 'code_revoked');
  END IF;
  IF v_inst.code_expires_at IS NOT NULL AND v_inst.code_expires_at < now() THEN
    RETURN jsonb_build_object('error', 'code_expired');
  END IF;
  SELECT * INTO v_existing FROM public.join_requests
    WHERE institution_id = v_inst.id AND applicant_email = p_email AND status = 'pending';
  IF FOUND THEN
    RETURN jsonb_build_object('error', 'duplicate_pending');
  END IF;
  SELECT * INTO v_existing FROM public.join_requests
    WHERE institution_id = v_inst.id AND applicant_email = p_email AND status = 'accepted';
  IF FOUND THEN
    RETURN jsonb_build_object('error', 'already_member');
  END IF;
  INSERT INTO public.join_requests (institution_id, applicant_email, applicant_name, status)
    VALUES (v_inst.id, p_email, p_full_name, 'pending');
  RETURN jsonb_build_object('success', true);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.submit_join_request(text, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.submit_join_request(text, text, text) TO authenticated;

-- 3. Recreate get_own_join_request_status with fixed search_path
CREATE OR REPLACE FUNCTION public.get_own_join_request_status()
RETURNS TABLE(status text, institution_name text, created_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_email text;
BEGIN
  SELECT email INTO v_email FROM auth.users WHERE id = auth.uid();
  RETURN QUERY
    SELECT jr.status::text, i.name, jr.created_at
    FROM public.join_requests jr
    JOIN public.institutions i ON i.id = jr.institution_id
    WHERE jr.applicant_email = v_email
    ORDER BY jr.created_at DESC
    LIMIT 1;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.get_own_join_request_status() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_own_join_request_status() TO authenticated;

-- 4. Recreate is_inst_member with fixed search_path
CREATE OR REPLACE FUNCTION public.is_inst_member(uid uuid, inst_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = ''
AS $$
  SELECT EXISTS (SELECT 1 FROM public.profiles p WHERE p.user_id = uid AND p.institution_id = inst_id);
$$;

-- 5. Recreate can_access_class with fixed search_path
CREATE OR REPLACE FUNCTION public.can_access_class(uid uuid, cls_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.user_id = uid
    AND p.institution_id = (SELECT c.institution_id FROM public.classes c WHERE c.id = cls_id)
    AND (p.role = 'admin' OR EXISTS (
      SELECT 1 FROM public.class_assignments ca WHERE ca.profile_id = uid AND ca.class_id = cls_id
    ))
  );
$$;

-- 6. Recreate calc_lesson_duration with fixed search_path
CREATE OR REPLACE FUNCTION public.calc_lesson_duration()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF NEW.end_time IS NOT NULL AND NEW.start_time IS NOT NULL THEN
    NEW.duration_minutes := (split_part(NEW.end_time, ':', 1)::int * 60 + split_part(NEW.end_time, ':', 2)::int)
                           - (split_part(NEW.start_time, ':', 1)::int * 60 + split_part(NEW.start_time, ':', 2)::int);
  END IF;
  RETURN NEW;
END;
$$;

-- 7. Recreate the trigger to point to the updated function
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
