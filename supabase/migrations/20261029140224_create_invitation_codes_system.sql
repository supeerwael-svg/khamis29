/*
# Invitation Codes System + Missing Supervisor RPCs

## Purpose
Adds a dedicated `invitation_codes` table so General Supervisors can create
custom invitation codes (e.g. "EDU2026DZ01") with optional expiration and
usage limits. Also creates the three RPCs the frontend already calls but
that were missing from the database (`regenerate_joining_code`,
`approve_join_request`, `reject_join_request`).

## Changes

### 1. New Table: `invitation_codes`
- `id` (uuid PK)
- `institution_id` (uuid FK → institutions, CASCADE)
- `code` (text, uppercase, unique among active codes)
- `created_by` (uuid FK → auth.users, SET NULL)
- `expires_at` (timestamptz, nullable — null = no expiration)
- `max_uses` (int, nullable — null = unlimited)
- `use_count` (int, default 0)
- `revoked_at` (timestamptz, nullable)
- `created_at` (timestamptz, default now())

### 2. RLS on `invitation_codes`
- SELECT: institution members (admin or supervisor) can see their institution's codes
- INSERT: only admins of the institution
- UPDATE: only admins (for revocation)
- DELETE: only admins
- GRANT SELECT, INSERT, UPDATE, DELETE TO authenticated

### 3. New RPC: `create_invitation_code(p_code, p_expires_in_hours, p_max_uses)`
- SECURITY DEFINER
- Validates: caller is admin of an institution, code format (A-Z0-9, 6-32 chars),
  no duplicate active code across ALL institutions (global uniqueness)
- Normalizes to uppercase
- Returns the created code row as JSON

### 4. New RPC: `revoke_invitation_code(p_code_id)`
- SECURITY DEFINER
- Sets `revoked_at = now()` if caller is admin of the code's institution

### 5. Updated RPC: `submit_join_request`
- Now checks `invitation_codes` table FIRST (custom codes)
- Falls back to the old `institutions.joining_code` column (backward compat)
- Increments `use_count` atomically; rejects if `max_uses` reached
- Rejects if code is revoked or expired
- All existing validation (duplicate pending, already member) preserved

### 6. New RPC: `regenerate_joining_code(p_inst_id)`
- SECURITY DEFINER — admin only
- Generates a random 8-char code and updates `institutions.joining_code`
- Sets `code_expires_at` to 24h from now, clears `code_revoked_at`
- Returns the new code text

### 7. New RPC: `approve_join_request(p_request_id)`
- SECURITY DEFINER — admin of the request's institution only
- Sets status to 'accepted', links the applicant's profile to the institution,
  creates an approved membership row

### 8. New RPC: `reject_join_request(p_request_id)`
- SECURITY DEFINER — admin of the request's institution only
- Sets status to 'rejected'

## Security
- All RPCs are SECURITY DEFINER with `SET search_path = ''`
- REVOKE from PUBLIC/anon, GRANT to authenticated only
- Only institution admins can create/revoke codes
- Codes are globally unique among active (non-revoked) codes
- Institution isolation enforced in all operations
*/

-- =========== INVITATION CODES TABLE ===========
CREATE TABLE IF NOT EXISTS invitation_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  institution_id uuid NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
  code text NOT NULL,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  expires_at timestamptz,
  max_uses integer,
  use_count integer NOT NULL DEFAULT 0,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_invcode_active ON invitation_codes(code) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_invcode_inst ON invitation_codes(institution_id);

ALTER TABLE invitation_codes ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON invitation_codes TO authenticated;

DROP POLICY IF EXISTS "invcode_select_inst" ON invitation_codes;
CREATE POLICY "invcode_select_inst" ON invitation_codes FOR SELECT TO authenticated
  USING (is_inst_member(auth.uid(), institution_id));

DROP POLICY IF EXISTS "invcode_insert_admin" ON invitation_codes;
CREATE POLICY "invcode_insert_admin" ON invitation_codes FOR INSERT TO authenticated
  WITH CHECK (EXISTS (SELECT 1 FROM profiles p WHERE p.user_id = auth.uid() AND p.institution_id = invitation_codes.institution_id AND p.role = 'admin'));

DROP POLICY IF EXISTS "invcode_update_admin" ON invitation_codes;
CREATE POLICY "invcode_update_admin" ON invitation_codes FOR UPDATE TO authenticated
  USING (EXISTS (SELECT 1 FROM profiles p WHERE p.user_id = auth.uid() AND p.institution_id = invitation_codes.institution_id AND p.role = 'admin'))
  WITH CHECK (EXISTS (SELECT 1 FROM profiles p WHERE p.user_id = auth.uid() AND p.institution_id = invitation_codes.institution_id AND p.role = 'admin'));

DROP POLICY IF EXISTS "invcode_delete_admin" ON invitation_codes;
CREATE POLICY "invcode_delete_admin" ON invitation_codes FOR DELETE TO authenticated
  USING (EXISTS (SELECT 1 FROM profiles p WHERE p.user_id = auth.uid() AND p.institution_id = invitation_codes.institution_id AND p.role = 'admin'));

-- =========== CREATE INVITATION CODE RPC ===========
CREATE OR REPLACE FUNCTION public.create_invitation_code(
  p_code text,
  p_expires_in_hours integer,
  p_max_uses integer
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_inst_id uuid;
  v_code text;
  v_existing text;
  v_expires timestamptz;
BEGIN
  IF v_user_id IS NULL THEN
    RETURN jsonb_build_object('error', 'not_authenticated');
  END IF;

  SELECT institution_id INTO v_inst_id FROM public.profiles WHERE user_id = v_user_id;
  IF v_inst_id IS NULL THEN
    RETURN jsonb_build_object('error', 'no_institution');
  END IF;

  IF public.get_my_role() != 'admin' THEN
    RETURN jsonb_build_object('error', 'not_admin');
  END IF;

  v_code := upper(btrim(p_code));
  IF v_code !~ '^[A-Z0-9]{6,32}$' THEN
    RETURN jsonb_build_object('error', 'invalid_code_format');
  END IF;

  SELECT code INTO v_existing FROM public.invitation_codes
    WHERE code = v_code AND revoked_at IS NULL
    LIMIT 1;
  IF FOUND THEN
    RETURN jsonb_build_object('error', 'duplicate_code');
  END IF;

  IF p_expires_in_hours IS NOT NULL AND p_expires_in_hours > 0 THEN
    v_expires := now() + (p_expires_in_hours || ' hours')::interval;
  END IF;

  IF p_max_uses IS NOT NULL AND p_max_uses <= 0 THEN
    p_max_uses := NULL;
  END IF;

  INSERT INTO public.invitation_codes (institution_id, code, created_by, expires_at, max_uses)
    VALUES (v_inst_id, v_code, v_user_id, v_expires, p_max_uses);

  RETURN jsonb_build_object('success', true, 'code', v_code);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.create_invitation_code(text, integer, integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_invitation_code(text, integer, integer) TO authenticated;

-- =========== REVOKE INVITATION CODE RPC ===========
CREATE OR REPLACE FUNCTION public.revoke_invitation_code(p_code_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_inst_id uuid;
  v_code_inst_id uuid;
BEGIN
  IF v_user_id IS NULL THEN
    RETURN jsonb_build_object('error', 'not_authenticated');
  END IF;

  SELECT institution_id INTO v_inst_id FROM public.profiles WHERE user_id = v_user_id;
  IF v_inst_id IS NULL THEN
    RETURN jsonb_build_object('error', 'no_institution');
  END IF;

  IF public.get_my_role() != 'admin' THEN
    RETURN jsonb_build_object('error', 'not_admin');
  END IF;

  SELECT institution_id INTO v_code_inst_id FROM public.invitation_codes WHERE id = p_code_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'code_not_found');
  END IF;

  IF v_code_inst_id != v_inst_id THEN
    RETURN jsonb_build_object('error', 'not_authorized');
  END IF;

  UPDATE public.invitation_codes SET revoked_at = now() WHERE id = p_code_id AND revoked_at IS NULL;

  RETURN jsonb_build_object('success', true);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.revoke_invitation_code(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.revoke_invitation_code(uuid) TO authenticated;

-- =========== UPDATED SUBMIT_JOIN_REQUEST ===========
CREATE OR REPLACE FUNCTION public.submit_join_request(p_institution_code text, p_email text, p_full_name text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_code text;
  v_inst public.institutions%ROWTYPE;
  v_inv public.invitation_codes%ROWTYPE;
  v_existing public.join_requests%ROWTYPE;
  v_found boolean;
BEGIN
  v_code := upper(btrim(p_institution_code));

  -- Try custom invitation_codes table first
  SELECT * INTO v_inv FROM public.invitation_codes
    WHERE code = v_code AND revoked_at IS NULL
    LIMIT 1;

  IF FOUND THEN
    -- Check expiration
    IF v_inv.expires_at IS NOT NULL AND v_inv.expires_at < now() THEN
      RETURN jsonb_build_object('error', 'code_expired');
    END IF;

    -- Check usage limit
    IF v_inv.max_uses IS NOT NULL AND v_inv.use_count >= v_inv.max_uses THEN
      RETURN jsonb_build_object('error', 'code_exhausted');
    END IF;

    -- Get the institution
    SELECT * INTO v_inst FROM public.institutions WHERE id = v_inv.institution_id;
    IF NOT FOUND THEN
      RETURN jsonb_build_object('error', 'invalid_code');
    END IF;

    -- Check for duplicate pending request
    SELECT * INTO v_existing FROM public.join_requests
      WHERE institution_id = v_inst.id AND applicant_email = p_email AND status = 'pending';
    IF FOUND THEN
      RETURN jsonb_build_object('error', 'duplicate_pending');
    END IF;

    -- Check for already accepted
    SELECT * INTO v_existing FROM public.join_requests
      WHERE institution_id = v_inst.id AND applicant_email = p_email AND status = 'accepted';
    IF FOUND THEN
      RETURN jsonb_build_object('error', 'already_member');
    END IF;

    -- Insert join request
    INSERT INTO public.join_requests (institution_id, applicant_email, applicant_name, status)
      VALUES (v_inst.id, p_email, p_full_name, 'pending');

    -- Atomically increment use_count (only if max_uses not exceeded)
    UPDATE public.invitation_codes
      SET use_count = use_count + 1
      WHERE id = v_inv.id
      AND (max_uses IS NULL OR use_count < max_uses);

    RETURN jsonb_build_object('success', true);
  END IF;

  -- Fall back to legacy institutions.joining_code
  SELECT * INTO v_inst FROM public.institutions WHERE joining_code = v_code;
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

-- =========== REGENERATE JOINING CODE RPC ===========
CREATE OR REPLACE FUNCTION public.regenerate_joining_code(p_inst uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_role text;
  v_new_code text;
  v_chars text := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  SELECT role INTO v_role FROM public.profiles WHERE user_id = v_user_id AND institution_id = p_inst;
  IF v_role IS NULL OR v_role != 'admin' THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;

  v_new_code := '';
  FOR i IN 1..8 LOOP
    v_new_code := v_new_code || substr(v_chars, floor(random() * 36)::int + 1, 1);
  END LOOP;

  UPDATE public.institutions
    SET joining_code = v_new_code,
        code_revoked_at = NULL,
        code_expires_at = now() + interval '24 hours'
    WHERE id = p_inst;

  RETURN v_new_code;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.regenerate_joining_code(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.regenerate_joining_code(uuid) TO authenticated;

-- =========== APPROVE JOIN REQUEST RPC ===========
CREATE OR REPLACE FUNCTION public.approve_join_request(p_request_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_role text;
  v_req public.join_requests%ROWTYPE;
  v_profile public.profiles%ROWTYPE;
BEGIN
  IF v_user_id IS NULL THEN
    RETURN jsonb_build_object('error', 'not_authenticated');
  END IF;

  SELECT * INTO v_req FROM public.join_requests WHERE id = p_request_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'request_not_found');
  END IF;

  SELECT role INTO v_role FROM public.profiles WHERE user_id = v_user_id AND institution_id = v_req.institution_id;
  IF v_role IS NULL OR v_role != 'admin' THEN
    RETURN jsonb_build_object('error', 'not_authorized');
  END IF;

  IF v_req.status != 'pending' THEN
    RETURN jsonb_build_object('error', 'already_decided');
  END IF;

  UPDATE public.join_requests SET status = 'accepted', decided_by = v_user_id, decided_at = now(), updated_at = now()
    WHERE id = p_request_id;

  -- Link the applicant's profile to the institution if they have an account
  SELECT * INTO v_profile FROM public.profiles WHERE email = v_req.applicant_email;
  IF FOUND THEN
    UPDATE public.profiles
      SET institution_id = v_req.institution_id,
          role = 'supervisor',
          full_name = v_req.applicant_name,
          updated_at = now()
      WHERE email = v_req.applicant_email;

    INSERT INTO public.memberships (user_id, institution_id, role, approved)
      VALUES (v_profile.user_id, v_req.institution_id, 'supervisor', true)
      ON CONFLICT DO NOTHING;
  END IF;

  RETURN jsonb_build_object('success', true);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.approve_join_request(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.approve_join_request(uuid) TO authenticated;

-- =========== REJECT JOIN REQUEST RPC ===========
CREATE OR REPLACE FUNCTION public.reject_join_request(p_request_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_role text;
  v_req public.join_requests%ROWTYPE;
BEGIN
  IF v_user_id IS NULL THEN
    RETURN jsonb_build_object('error', 'not_authenticated');
  END IF;

  SELECT * INTO v_req FROM public.join_requests WHERE id = p_request_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'request_not_found');
  END IF;

  SELECT role INTO v_role FROM public.profiles WHERE user_id = v_user_id AND institution_id = v_req.institution_id;
  IF v_role IS NULL OR v_role != 'admin' THEN
    RETURN jsonb_build_object('error', 'not_authorized');
  END IF;

  IF v_req.status != 'pending' THEN
    RETURN jsonb_build_object('error', 'already_decided');
  END IF;

  UPDATE public.join_requests SET status = 'rejected', decided_by = v_user_id, decided_at = now(), updated_at = now()
    WHERE id = p_request_id;

  RETURN jsonb_build_object('success', true);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.reject_join_request(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.reject_join_request(uuid) TO authenticated;
