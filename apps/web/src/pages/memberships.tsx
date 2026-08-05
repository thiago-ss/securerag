import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { api, ApiError } from '../api';
import type { GroupRecord, MembershipRecord } from '../types';
import { useSession } from '../session';
import {
  EmptyState,
  ErrorNotice,
  FocusHeading,
  Loading,
  PageSection,
  SelectField,
  SuccessNotice,
  TextField,
} from '../components/ui';

type MembersState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; members: MembershipRecord[] };

type GroupsState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; groups: GroupRecord[] };

/** Memberships + groups management (tenant admin flows; the API is the gate —
 * non-admin writes are indistinguishable 404s). */
export function MembershipsPage(): ReactNode {
  const session = useSession();
  const tenantId = session.tenantId;
  const [members, setMembers] = useState<MembersState>({ kind: 'loading' });
  const [groups, setGroups] = useState<GroupsState>({ kind: 'loading' });
  const [notice, setNotice] = useState<string | null>(null);

  const loadMembers = useCallback(async (): Promise<void> => {
    if (tenantId === null) {
      setMembers({ kind: 'error', message: 'You have no tenant membership yet.' });
      return;
    }
    setMembers({ kind: 'loading' });
    try {
      const { members: list } = await api.listMemberships(tenantId);
      setMembers({ kind: 'ready', members: list });
    } catch (err) {
      setMembers({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not load memberships',
      });
    }
  }, [tenantId]);

  const loadGroups = useCallback(async (): Promise<void> => {
    if (tenantId === null) {
      setGroups({ kind: 'error', message: 'You have no tenant membership yet.' });
      return;
    }
    setGroups({ kind: 'loading' });
    try {
      const { groups: list } = await api.listGroups(tenantId);
      setGroups({ kind: 'ready', groups: list });
    } catch (err) {
      setGroups({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not load groups',
      });
    }
  }, [tenantId]);

  useEffect(() => {
    void loadMembers();
    void loadGroups();
  }, [loadMembers, loadGroups]);

  const refresh = async (): Promise<void> => {
    await Promise.all([loadMembers(), loadGroups()]);
  };

  const act = async (action: () => Promise<unknown>, okMessage: string): Promise<void> => {
    try {
      await action();
      setNotice(okMessage);
      await refresh();
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : 'Operation failed');
    }
  };

  return (
    <div className="page">
      <FocusHeading>Members and groups</FocusHeading>
      {notice !== null ? <SuccessNotice>{notice}</SuccessNotice> : null}
      <PageSection title="Members">
        {members.kind === 'loading' ? <Loading label="Loading members" /> : null}
        {members.kind === 'error' ? <ErrorNotice message={members.message} /> : null}
        {members.kind === 'ready' ? (
          <>
            <MemberTable members={members.members} onAct={act} />
            <AddMemberForm tenantId={tenantId} onAct={act} />
          </>
        ) : null}
      </PageSection>
      <PageSection title="Groups">
        {groups.kind === 'loading' ? <Loading label="Loading groups" /> : null}
        {groups.kind === 'error' ? <ErrorNotice message={groups.message} /> : null}
        {groups.kind === 'ready' ? (
          <>
            {groups.groups.length === 0 ? (
              <EmptyState>No groups yet.</EmptyState>
            ) : (
              groups.groups.map((group) => (
                <GroupRow
                  key={group.groupId}
                  group={group}
                  tenantId={tenantId}
                  onAct={act}
                />
              ))
            )}
            <AddGroupForm tenantId={tenantId} onAct={act} />
          </>
        ) : null}
      </PageSection>
    </div>
  );
}

function MemberTable({
  members,
  onAct,
}: {
  members: MembershipRecord[];
  onAct: (action: () => Promise<unknown>, okMessage: string) => Promise<void>;
}): ReactNode {
  return (
    <table className="data-table">
      <caption className="sr-only">Tenant memberships</caption>
      <thead>
        <tr>
          <th scope="col">Principal</th>
          <th scope="col">Role</th>
          <th scope="col">Active</th>
          <th scope="col">Joined</th>
          <th scope="col">
            <span className="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {members.map((member) => (
          <tr key={member.membershipId}>
            <td>
              <code>{member.principalId}</code>
            </td>
            <td>
              <RoleSelect
                member={member}
                onAct={onAct}
              />
            </td>
            <td>{member.isActive ? 'yes' : 'no'}</td>
            <td>{member.joinedAt}</td>
            <td>
              <div className="row-actions">
                <button
                  type="button"
                  className="button button-small"
                  onClick={() =>
                    void onAct(
                      () => api.patchMembership({ tenantId: member.tenantId, principalId: member.principalId, isActive: !member.isActive }),
                      member.isActive ? 'Membership deactivated.' : 'Membership activated.',
                    )
                  }
                >
                  {member.isActive ? 'Deactivate' : 'Activate'}
                </button>
                <button
                  type="button"
                  className="button button-small button-danger"
                  onClick={() =>
                    void onAct(
                      () => api.removeMembership(member.tenantId, member.principalId),
                      'Membership removed.',
                    )
                  }
                >
                  Remove
                </button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RoleSelect({
  member,
  onAct,
}: {
  member: MembershipRecord;
  onAct: (action: () => Promise<unknown>, okMessage: string) => Promise<void>;
}): ReactNode {
  const [busy, setBusy] = useState(false);
  return (
    <select
      aria-label={`Role of ${member.principalId.slice(0, 8)}`}
      value={member.role}
      disabled={busy}
      onChange={(event) => {
        const role = event.target.value;
        setBusy(true);
        void onAct(
          () => api.patchMembership({ tenantId: member.tenantId, principalId: member.principalId, role }),
          `Role changed to ${role}.`,
        ).finally(() => setBusy(false));
      }}
    >
      <option value="member">member</option>
      <option value="admin">admin</option>
      <option value="security_reviewer">security_reviewer</option>
    </select>
  );
}

function AddMemberForm({
  tenantId,
  onAct,
}: {
  tenantId: string | null;
  onAct: (action: () => Promise<unknown>, okMessage: string) => Promise<void>;
}): ReactNode {
  const [principalId, setPrincipalId] = useState('');
  const [role, setRole] = useState('member');
  const submit = (event: FormEvent): void => {
    event.preventDefault();
    if (tenantId === null || principalId.trim() === '') return;
    void onAct(
      () => api.addMembership({ tenantId, principalId: principalId.trim(), role }),
      'Membership added.',
    ).then(() => setPrincipalId(''));
  };
  return (
    <form className="inline-form" onSubmit={submit}>
      <TextField label="Principal id" value={principalId} onChange={(e) => setPrincipalId(e.target.value)} placeholder="uuid" />
      <SelectField label="Role" value={role} onChange={(e) => setRole(e.target.value)}>
        <option value="member">member</option>
        <option value="admin">admin</option>
        <option value="security_reviewer">security_reviewer</option>
      </SelectField>
      <button type="submit" className="button button-primary" disabled={tenantId === null || principalId.trim() === ''}>
        Add member
      </button>
    </form>
  );
}

function AddGroupForm({
  tenantId,
  onAct,
}: {
  tenantId: string | null;
  onAct: (action: () => Promise<unknown>, okMessage: string) => Promise<void>;
}): ReactNode {
  const [name, setName] = useState('');
  const submit = (event: FormEvent): void => {
    event.preventDefault();
    if (tenantId === null || name.trim() === '') return;
    void onAct(() => api.createGroup(tenantId, name.trim()), 'Group created.').then(() => setName(''));
  };
  return (
    <form className="inline-form" onSubmit={submit}>
      <TextField label="Group name" value={name} onChange={(e) => setName(e.target.value)} />
      <button type="submit" className="button button-primary" disabled={tenantId === null || name.trim() === ''}>
        Create group
      </button>
    </form>
  );
}

function GroupRow({
  group,
  tenantId,
  onAct,
}: {
  group: GroupRecord;
  tenantId: string | null;
  onAct: (action: () => Promise<unknown>, okMessage: string) => Promise<void>;
}): ReactNode {
  const [principalId, setPrincipalId] = useState('');
  return (
    <div className="group-row">
      <div className="group-heading">
        <strong>{group.name}</strong>{' '}
        <span className="status-text">
          <code>{group.groupId}</code>
        </span>
        <button
          type="button"
          className="button button-small button-danger"
          onClick={() => void onAct(() => api.deleteGroup(group.tenantId, group.groupId), 'Group deleted.')}
        >
          Delete group
        </button>
      </div>
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (tenantId === null || principalId.trim() === '') return;
          void onAct(() => api.addGroupMember(group.groupId, { tenantId, principalId: principalId.trim() }), 'Member added to group.').then(
            () => setPrincipalId(''),
          );
        }}
      >
        <TextField label={`Add member to ${group.name}`} value={principalId} onChange={(e) => setPrincipalId(e.target.value)} placeholder="principal uuid" />
        <button type="submit" className="button button-primary" disabled={tenantId === null || principalId.trim() === ''}>
          Add to group
        </button>
      </form>
    </div>
  );
}
