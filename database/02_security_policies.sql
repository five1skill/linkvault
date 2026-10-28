
-- 1. Вспомогательные функции для проверки доступа
create schema if not exists private;

create or replace function private.is_admin()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and is_admin = true
  );
$$;

create or replace function private.owns_folder(p_folder_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.folders
    where id = p_folder_id
      and created_by = (select auth.uid())
  );
$$;

create or replace function private.can_access_folder(p_folder_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select private.is_admin() or exists (
    select 1 from public.folder_access
    where folder_id = p_folder_id
      and user_id = (select auth.uid())
  );
$$;

create or replace function private.can_access_link(p_link_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.saved_links l
    where l.id = p_link_id
      and private.can_access_folder(l.folder_id)
  );
$$;

-- 2. Ограничиваем вызов служебных функций
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;

revoke all on function private.is_admin() from public, anon;
revoke all on function private.owns_folder(uuid) from public, anon;
revoke all on function private.can_access_folder(uuid) from public, anon;
revoke all on function private.can_access_link(uuid) from public, anon;

grant execute on function private.is_admin() to authenticated;
grant execute on function private.owns_folder(uuid) to authenticated;
grant execute on function private.can_access_folder(uuid) to authenticated;
grant execute on function private.can_access_link(uuid) to authenticated;

-- 3. Убираем прямой доступ к таблицам для посетителей
revoke all on table public.profiles,
  public.folders,
  public.folder_access,
  public.saved_links,
  public.link_authors
from anon, authenticated;

-- 4. Выдаём авторизованным только нужные операции
grant select on public.profiles to authenticated;

grant select, insert, update, delete
on public.folders to authenticated;

grant select, insert, delete
on public.folder_access to authenticated;

grant select, insert, update, delete
on public.saved_links to authenticated;

grant select, insert, delete
on public.link_authors to authenticated;

-- 5. Профили видны только вошедшим пользователям
create policy "profiles_read_authenticated"
on public.profiles for select
to authenticated
using (true);

-- 6. Папки: просмотр, создание и управление
create policy "folders_read_accessible"
on public.folders for select
to authenticated
using (private.can_access_folder(id));

create policy "folders_create_own"
on public.folders for insert
to authenticated
with check (created_by = (select auth.uid()));

create policy "folders_update_owner_or_admin"
on public.folders for update
to authenticated
using (
  created_by = (select auth.uid()) or private.is_admin()
)
with check (
  created_by = (select auth.uid()) or private.is_admin()
);

create policy "folders_delete_owner_or_admin"
on public.folders for delete
to authenticated
using (
  created_by = (select auth.uid()) or private.is_admin()
);

-- 7. Доступ к папкам
create policy "access_read_own_or_admin"
on public.folder_access for select
to authenticated
using (
  user_id = (select auth.uid()) or private.is_admin()
);

create policy "access_add_self_or_admin"
on public.folder_access for insert
to authenticated
with check (
  private.is_admin()
  or (
    user_id = (select auth.uid())
    and private.owns_folder(folder_id)
  )
);

create policy "access_delete_admin"
on public.folder_access for delete
to authenticated
using (private.is_admin());

-- 8. Ссылки
create policy "links_read_accessible"
on public.saved_links for select
to authenticated
using (private.can_access_folder(folder_id));

create policy "links_create_accessible"
on public.saved_links for insert
to authenticated
with check (
  created_by = (select auth.uid())
  and private.can_access_folder(folder_id)
);

create policy "links_update_owner_or_admin"
on public.saved_links for update
to authenticated
using (
  created_by = (select auth.uid()) or private.is_admin()
)
with check (
  created_by = (select auth.uid()) or private.is_admin()
);

create policy "links_delete_owner_or_admin"
on public.saved_links for delete
to authenticated
using (
  created_by = (select auth.uid()) or private.is_admin()
);

-- 9. Авторы сохранённых ссылок
create policy "authors_read_accessible_links"
on public.link_authors for select
to authenticated
using (private.can_access_link(link_id));

create policy "authors_add_self"
on public.link_authors for insert
to authenticated
with check (
  user_id = (select auth.uid())
  and private.can_access_link(link_id)
);

create policy "authors_delete_self_or_admin"
on public.link_authors for delete
to authenticated
using (
  user_id = (select auth.uid()) or private.is_admin()
);
