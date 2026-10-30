import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import LandingPage from './pages/LandingPage'
import DashboardPage from './pages/DashboardPage'
import AnalysisPage from './pages/AnalysisPage'
import ResultsPage from './pages/ResultsPage'
import AboutPage from './pages/AboutPage'

function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/analyze" element={<AnalysisPage />} />
          <Route path="/results" element={<ResultsPage />} />
          <Route path="/about" element={<AboutPage />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}

export default App
