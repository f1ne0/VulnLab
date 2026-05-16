import { createBrowserRouter } from 'react-router-dom'
import { AppShell } from '../layout/AppShell'
import HomePage from '../pages/Home'
import LabPage from '../pages/Lab'
import VulnerabilitiesPage from '../pages/Vulnerabilities'
import VulnerabilityDetailPage from '../pages/Vulnerabilities/[id]'
import ThreatModelPage from '../pages/ThreatModel'
import LegalPage from '../pages/Legal'
import OwaspPage from '../pages/OWASP'
import ReportsPage from '../pages/Reports'
import AboutPage from '../pages/About'

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true, element: <HomePage /> },
      { path: 'lab', element: <LabPage /> },
      { path: 'vulnerabilities', element: <VulnerabilitiesPage /> },
      { path: 'vulnerabilities/:id', element: <VulnerabilityDetailPage /> },
      { path: 'threat-model', element: <ThreatModelPage /> },
      { path: 'legal', element: <LegalPage /> },
      { path: 'owasp', element: <OwaspPage /> },
      { path: 'reports', element: <ReportsPage /> },
      { path: 'about', element: <AboutPage /> }
    ]
  }
])
