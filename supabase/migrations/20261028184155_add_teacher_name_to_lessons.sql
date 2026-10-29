/*
# Add teacher_name column to lessons table

## Changes
1. Adds `teacher_name` (text, nullable) to the `lessons` table so that each
   lesson can store the teacher's name as parsed from the Excel timetable import.
2. The column is nullable because existing lessons and lessons without an
   assigned teacher are valid — the column only gets populated when a teacher
   name is present in the imported Excel file.
3. No RLS policy changes needed — the existing `can_access_class` policies
   already govern all CRUD on the `lessons` table, and the new column is
   accessible to anyone who can already read/write the row.
*/

ALTER TABLE lessons ADD COLUMN IF NOT EXISTS teacher_name text;
