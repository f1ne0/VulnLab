import { Radar } from 'react-chartjs-2'
import { Chart as ChartJS, Filler, Legend, LineElement, PointElement, RadialLinearScale, Tooltip } from 'chart.js'
import type { Locale } from '../../i18n'

ChartJS.register(RadialLinearScale, PointElement, LineElement, Filler, Tooltip, Legend)

export function RadarChart({ values, labels, locale = 'ru' }: { values: number[]; labels: string[]; locale?: Locale }) {
  return (
    <Radar
      data={{
        labels,
        datasets: [
          {
            label: locale === 'ru' ? 'Профиль риска' : 'Risk profile',
            data: values,
            backgroundColor: 'rgba(0,255,178,0.12)',
            borderColor: '#00FFB2',
            pointBackgroundColor: '#00FFB2'
          }
        ]
      }}
      options={{
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          r: {
            suggestedMin: 0,
            suggestedMax: 10,
            grid: { color: 'rgba(255,255,255,0.08)' },
            pointLabels: { color: '#c2fff0' },
            ticks: { backdropColor: 'transparent', color: '#89d9c0' }
          }
        }
      }}
    />
  )
}
