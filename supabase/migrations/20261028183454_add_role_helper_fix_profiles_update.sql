/*
# Add get_my_role() helper and simplify profiles UPDATE policy

## Problem
The updated `prof_update_self_or_admin` policy still contains a direct subquery
`SELECT p.role FROM profiles p WHERE p.user_id = auth.uid()`. While this doesn't
cause infinite recursion (because the profiles SELECT policy uses get_my_institution_id()
which is SECURITY DEFINER and bypasses RLS), it's cleaner and safer to use a
dedicated helper function for the role check too.

## Solution
Created `get_my_role()` — SECURITY DEFINER function returning the caller's role.
Rewrote the UPDATE policy to use both `get_my_institution_id()` and `get_my_role()`.
*/

CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT role FROM public.profiles WHERE user_id = auth.uid();
$$;

REVOKE EXECUTE ON FUNCTION public.get_my_role() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_my_role() TO authenticated;

-- Recreate the UPDATE policy using both helpers (no direct profiles subqueries)
DROP POLICY IF EXISTS prof_update_self_or_admin ON profiles;

CREATE POLICY prof_update_self_or_admin ON profiles
  FOR UPDATE TO authenticated
  USING (
    auth.uid() = user_id
    OR (
      institution_id IS NOT NULL
      AND institution_id = public.get_my_institution_id()
      AND public.get_my_role() = 'admin'
    )
  )
  WITH CHECK (
    auth.uid() = user_id
    OR (
      institution_id IS NOT NULL
      AND institution_id = public.get_my_institution_id()
      AND public.get_my_role() = 'admin'
    )
  );
