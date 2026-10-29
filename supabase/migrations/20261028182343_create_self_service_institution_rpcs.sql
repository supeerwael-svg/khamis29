/*
# Create self-service institution creation + join RPCs

## Problem
Users who sign up but fail to link to an institution (e.g. admin signup RPC failed,
or account was created outside the normal flow) hit a dead-end "No institution linked"
screen with no way forward except signing out.

## Solution
Two new SECURITY DEFINER RPCs:

### 1. `create_own_institution(p_name text, p_full_name text)`
For users who want to create a new institution and become its admin.
- Creates a new institution row
- Links the caller's profile to it with role='admin'
- Creates an approved membership
- Returns the institution id
Only callable by authenticated users. A user can only have one institution link.

### 2. `list_joinable_institutions()`
Returns institutions that the caller is not yet a member of, so they can
choose one to request joining. Returns id + name only (no joining codes).

## Security
- Both SECURITY DEFINER with fixed search_path = ''
- REVOKE from anon/PUBLIC, GRANT to authenticated only
- create_own_institution only updates the caller's own profile
- list_joinable_institutions excludes institutions the user already belongs to
*/

CREATE OR REPLACE FUNCTION public.create_own_institution(p_name text, p_full_name text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_inst_id uuid;
  v_existing_inst_id uuid;
BEGIN
  IF v_user_id IS NULL THEN
    RETURN jsonb_build_object('error', 'not_authenticated');
  END IF;

  -- Check if user already has an institution
  SELECT institution_id INTO v_existing_inst_id FROM public.profiles WHERE user_id = v_user_id;
  IF v_existing_inst_id IS NOT NULL THEN
    RETURN jsonb_build_object('error', 'already_has_institution', 'institution_id', v_existing_inst_id);
  END IF;

  -- Create the institution
  INSERT INTO public.institutions (name)
  VALUES (p_name)
  RETURNING id INTO v_inst_id;

  -- Link profile as admin
  UPDATE public.profiles
  SET institution_id = v_inst_id,
      role = 'admin',
      full_name = p_full_name,
      updated_at = now()
  WHERE user_id = v_user_id;

  -- Create approved membership
  INSERT INTO public.memberships (user_id, institution_id, role, approved)
  VALUES (v_user_id, v_inst_id, 'admin', true)
  ON CONFLICT DO NOTHING;

  RETURN jsonb_build_object('success', true, 'institution_id', v_inst_id);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.create_own_institution(text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_own_institution(text, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.list_joinable_institutions()
RETURNS TABLE(id uuid, name text)
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = ''
AS $$
  SELECT i.id, i.name
  FROM public.institutions i
  WHERE NOT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.user_id = auth.uid() AND p.institution_id = i.id
  )
  ORDER BY i.name;
$$;

REVOKE EXECUTE ON FUNCTION public.list_joinable_institutions() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.list_joinable_institutions() TO authenticated;
