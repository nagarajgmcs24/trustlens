import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 20000,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const analyzeMessage = async (payload) => {
  const response = await api.post('/api/analyze', payload)
  return response.data
}

export const getHealthStatus = async () => {
  const response = await api.get('/api/health')
  return response.data
}

export const getHistory = async () => {
  const response = await api.get('/api/history')
  return response.data.history || []
}

export const clearHistory = async () => {
  const response = await api.delete('/api/history')
  return response.data
}
