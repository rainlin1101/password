import { Navigate, Route, Routes } from 'react-router-dom'
import { CategoryPage } from './pages/CategoryPage'
import { HomePage } from './pages/HomePage'
import { QuizPage } from './pages/QuizPage'
import { ResultPage } from './pages/ResultPage'
import { WrongBookPage } from './pages/WrongBookPage'

function App() {
  return (
    <main className="mx-auto min-h-screen w-full max-w-md px-4 py-4">
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/quiz" element={<QuizPage />} />
        <Route path="/result" element={<ResultPage />} />
        <Route path="/wrong-book" element={<WrongBookPage />} />
        <Route path="/category" element={<CategoryPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </main>
  )
}

export default App
