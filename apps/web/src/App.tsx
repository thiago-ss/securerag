import { type ReactNode } from 'react';
import { parseRoute, useHashRoute } from './router';
import { SessionGate, useSession } from './session';
import { LoginPage, Shell } from './shell';
import { DocumentsPage } from './pages/documents';
import { DocumentDetailPage } from './pages/document-detail';
import { SearchPage } from './pages/search';
import { QuarantinePage } from './pages/quarantine';
import { AuditPage } from './pages/audit';
import { PolicyPage } from './pages/policy';
import { MembershipsPage } from './pages/memberships';
import { RefusalsPage } from './pages/refusals';

function AnonymousGate({ children }: { children: ReactNode }): ReactNode {
  const session = useSession();
  if (session.me !== null) return children;
  return <LoginPage />;
}

function Router(): ReactNode {
  const route = useHashRoute();
  const { segments } = parseRoute(route);
  const first = segments[0] ?? 'documents';

  switch (first) {
    case 'documents':
      return segments[1] !== undefined ? (
        <DocumentDetailPage documentId={segments[1] ?? ''} />
      ) : (
        <DocumentsPage />
      );
    case 'search':
      return <SearchPage />;
    case 'quarantine':
      return <QuarantinePage />;
    case 'audit':
      return <AuditPage />;
    case 'policy':
      return <PolicyPage />;
    case 'memberships':
      return <MembershipsPage />;
    case 'refusals':
      return <RefusalsPage />;
    default:
      return <DocumentsPage />;
  }
}

export default function App(): ReactNode {
  return (
    <SessionGate>
      <AnonymousGate>
        <Shell>
          <Router />
        </Shell>
      </AnonymousGate>
    </SessionGate>
  );
}
