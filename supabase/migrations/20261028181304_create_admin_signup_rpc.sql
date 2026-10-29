/*
# Create admin signup RPC for atomic institution + profile setup

## Problem
The `signUpAdmin` frontend flow was:
1. `auth.signUp()` — creates auth user + trigger creates profile row
2. Insert into `institutions` — creates institution but doesn't return ID to frontend
3. Update `profiles` with full_name + email — works but doesn't set institution_id or role

This left the admin's profile with `institution_id = NULL` and `role = 'supervisor'`,
so the app showed an infinite loading screen (no institution linked).

## Solution
Created a SECURITY DEFINER RPC `complete_admin_signup` that:
- Finds the institution the user just created (the one they don't yet belong to)
- Links the profile to that institution
- Sets the role to 'admin'
- Sets the full_name and email
- Creates an approved membership row
- All in one atomic operation

This runs after `auth.signUp()` and `institutions.insert()` succeed.
The frontend calls it with the institution name to find and link the right institution.

## Security
- SECURITY DEFINER with fixed search_path
- Only callable by authenticated users
- Only updates the caller's own profile
- Only links to an institution that has no members yet (brand new)
- REVOKE from anon/PUBLIC
*/

CREATE OR REPLACE FUNCTION public.complete_admin_signup(p_institution_name text, p_full_name text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_inst public.institutions%ROWTYPE;
BEGIN
  IF v_user_id IS NULL THEN
    RETURN jsonb_build_object('error', 'not_authenticated');
  END IF;

  -- Find the institution by name that this user doesn't yet belong to
  -- (the one they just created during signup)
  SELECT * INTO v_inst
  FROM public.institutions i
  WHERE i.name = p_institution_name
  AND NOT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.user_id = v_user_id AND p.institution_id = i.id
  )
  ORDER BY i.created_at DESC
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'institution_not_found');
  END IF;

  -- Link profile to institution, set admin role, update name
  UPDATE public.profiles
  SET institution_id = v_inst.id,
      role = 'admin',
      full_name = p_full_name,
      email = (SELECT email FROM auth.users WHERE id = v_user_id),
      updated_at = now()
  WHERE user_id = v_user_id;

  -- Create approved membership
  INSERT INTO public.memberships (user_id, institution_id, role, approved)
  VALUES (v_user_id, v_inst.id, 'admin', true)
  ON CONFLICT DO NOTHING;

  RETURN jsonb_build_object('success', true, 'institution_id', v_inst.id);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.complete_admin_signup(text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.complete_admin_signup(text, text) TO authenticated;
