import { GenericLab } from './GenericLab'
import { simulateFileUpload } from '../../utils/simulators/fileUploadSimulator'
import { useI18n } from '../../i18n'

export function FileUploadLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'File Upload',
        defaultPayload: 'shell.php',
        payloadLabel: isRu ? 'Имя файла' : 'Filename',
        inputSize: 'short',
        defaultScenario: { validation: 'extension', storage: 'webroot', mime: 'image/jpeg' },
        scenarioControls: [
          {
            type: 'select',
            key: 'validation',
            label: isRu ? 'Валидация' : 'Validation',
            options: [
              { value: 'none', label: isRu ? 'нет' : 'none' },
              { value: 'extension', label: 'extension blacklist' },
              { value: 'mime', label: 'Content-Type only' },
              { value: 'magic', label: 'magic bytes' }
            ]
          },
          {
            type: 'select',
            key: 'storage',
            label: isRu ? 'Хранение' : 'Storage',
            options: [
              { value: 'webroot', label: 'web-root' },
              { value: 'outside', label: 'outside web-root' }
            ]
          },
          { type: 'text', key: 'mime', label: 'Content-Type', placeholder: 'image/jpeg' }
        ],
        presets: [
          { id: 'php', title: 'shell.php', payload: 'shell.php' },
          { id: 'double', title: 'double ext shell.php.jpg', payload: 'shell.php.jpg' },
          { id: 'phar', title: 'phar deserialization', payload: 'payload.phar' },
          { id: 'jsp', title: 'cmd.jsp (Tomcat)', payload: 'cmd.jsp' },
          { id: 'svg', title: 'evil.svg (XSS)', payload: 'evil.svg' },
          { id: 'null', title: 'shell.php\\0.jpg', payload: 'shell.php .jpg' },
          { id: 'safe', title: 'avatar.png', payload: 'avatar.png' }
        ],
        simulate: (payload, scenario, loc) => simulateFileUpload(payload, scenario, loc)
      }}
    />
  )
}
