/*
# Fix infinite recursion in profiles RLS policies

## Problem
The `prof_select_self_or_inst` and `prof_update_self_or_admin` policies on the `profiles`
table both contain a subquery `SELECT 1 FROM profiles p WHERE ...` — querying the same
table that the policy is defined on. This causes PostgreSQL to evaluate the SELECT policy
recursively, leading to "infinite recursion detected in policy for relation 'profiles'".

## Solution
1. Created `get_my_institution_id()` — a SECURITY DEFINER function that returns the
   caller's institution_id. Because it runs as the function owner (postgres) with
   SECURITY DEFINER, it bypasses RLS entirely, so querying `profiles` inside it does
   NOT re-trigger the profiles SELECT policy.

2. Rewrote the two recursive profiles policies to use `get_my_institution_id()` instead
   of subquerying `profiles` directly:
   - `prof_select_self_or_inst`: can see own row OR anyone in the same institution
   - `prof_update_self_or_admin`: can update own row OR any row in own institution if admin

3. Also fixed `prof_update_self_or_admin` WITH CHECK — was `true` (allowing any update),
   now properly restricts to self or same-institution admin.

## Security
- `get_my_institution_id()` is SECURITY DEFINER with fixed search_path, only reads
  the profiles table, returns a single uuid. REVOKE from anon/PUBLIC.
- No data is exposed beyond what the original policies allowed.
*/

CREATE OR REPLACE FUNCTION public.get_my_institution_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT institution_id FROM public.profiles WHERE user_id = auth.uid();
$$;

REVOKE EXECUTE ON FUNCTION public.get_my_institution_id() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_my_institution_id() TO authenticated;

-- Drop the recursive policies
DROP POLICY IF EXISTS prof_select_self_or_inst ON profiles;
DROP POLICY IF EXISTS prof_update_self_or_admin ON profiles;

-- Recreate without recursion: use get_my_institution_id() instead of subquerying profiles
CREATE POLICY prof_select_self_or_inst ON profiles
  FOR SELECT TO authenticated
  USING (
    auth.uid() = user_id
    OR (
      institution_id IS NOT NULL
      AND institution_id = public.get_my_institution_id()
    )
  );

CREATE POLICY prof_update_self_or_admin ON profiles
  FOR UPDATE TO authenticated
  USING (
    auth.uid() = user_id
    OR (
      institution_id IS NOT NULL
      AND institution_id = public.get_my_institution_id()
      AND (
        SELECT p.role FROM public.profiles p WHERE p.user_id = auth.uid()
      ) = 'admin'
    )
  )
  WITH CHECK (
    auth.uid() = user_id
    OR (
      institution_id IS NOT NULL
      AND institution_id = public.get_my_institution_id()
      AND (
        SELECT p.role FROM public.profiles p WHERE p.user_id = auth.uid()
      ) = 'admin'
    )
  );
