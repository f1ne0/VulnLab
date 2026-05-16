import { Chart as ChartJS, CategoryScale, Legend, LineElement, LinearScale, PointElement, Tooltip } from 'chart.js'
import { Line } from 'react-chartjs-2'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend)

export function TrendLine({ labels, data2017, data2021 }: { labels: string[]; data2017: number[]; data2021: number[] }) {
  return (
    <Line
      data={{
        labels,
        datasets: [
          { label: '2017', data: data2017, borderColor: '#FFB800', backgroundColor: 'rgba(255,184,0,0.2)' },
          { label: '2021', data: data2021, borderColor: '#00FFB2', backgroundColor: 'rgba(0,255,178,0.2)' }
        ]
      }}
      options={{
        responsive: true,
        plugins: { legend: { labels: { color: '#d7fff5' } } },
        scales: {
          x: { ticks: { color: '#b9f5e6' }, grid: { color: 'rgba(255,255,255,0.06)' } },
          y: { reverse: true, ticks: { color: '#b9f5e6' }, grid: { color: 'rgba(255,255,255,0.06)' } }
        }
      }}
    />
  )
}
