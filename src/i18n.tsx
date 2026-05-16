import { Button, ButtonGroup } from '@chakra-ui/react'
import { createContext, useContext, useEffect, useMemo, useState, type PropsWithChildren } from 'react'

export type Locale = 'ru' | 'en'

const messages = {
  ru: {
    'nav.dashboard': 'Командный центр',
    'nav.lab': 'Лаборатория',
    'nav.vulns': 'Уязвимости',
    'nav.threat': 'Модель угроз',
    'nav.legal': 'Право',
    'nav.owasp': 'OWASP',
    'nav.reports': 'Отчёты',
    'nav.about': 'О проекте',
    'search.placeholder': 'Поиск уязвимостей, законов, пресетов',
    'search.label': 'Глобальный поиск',
    'topbar.themeHint': 'Язык интерфейса',
    'ethics.title': 'Этическое подтверждение',
    'ethics.body':
      'Все симуляции выполняются локально в браузере. Использование данных техник против реальных систем без разрешения является уголовно наказуемым. Платформа предназначена только для образовательных и исследовательских целей.',
    'ethics.confirm': 'Я подтверждаю образовательное использование',
    'shell.classifiedNode': 'ЗАСЕКРЕЧЕННЫЙ ИССЛЕДОВАТЕЛЬСКИЙ УЗЕЛ',
    'shell.ethicsStamp': 'ЗАСЕКРЕЧЕНО / ТРЕБУЕТСЯ ЭТИЧЕСКОЕ ПОДТВЕРЖДЕНИЕ',
    'common.educationalOnly': 'Только учебная песочница',
    'common.localDisclaimer':
      'Все симуляции выполняются локально в браузере. Использование данных техник против реальных систем без разрешения является уголовно наказуемым.',
    'common.detectedTechnique': 'Обнаруженная техника',
    'common.runAt': 'Последний запуск',
    'common.executed': 'Симуляция выполнена',
    'home.kicker': 'DARKNET RESEARCH LAB / КОМАНДНЫЙ ЦЕНТР',
    'home.title': 'Анализ и моделирование уязвимостей веб‑приложений с оценкой правовых последствий их эксплуатаций',
    'home.subtitle':
      'Платформа объединяет технический анализ, моделирование атак, отчётность и сравнительный правовой разбор последствий эксплуатации уязвимостей.',
    'home.openLab': 'Открыть лабораторию',
    'home.openDb': 'Просмотр базы угроз',
    'home.stats.vulns': 'Классы уязвимостей',
    'home.stats.jurisdictions': 'Правовые юрисдикции',
    'home.stats.owasp': 'Референсный год OWASP',
    'home.features.sim': 'Интерактивные симуляторы',
    'home.features.legal': 'Правовая аналитика',
    'home.features.report': 'Дипломная отчётность',
    'lab.title': 'Интерактивная лаборатория уязвимостей',
    'lab.subtitle':
      'Все симуляторы работают локально, сохраняют сессии и автоматически показывают технику атаки и правовой риск.',
    'lab.toast.title': 'Этическое напоминание',
    'lab.toast.body': 'Лаборатория выполняет только локальные симуляции. Тестирование реальных систем без разрешения незаконно.',
    'lab.sqli.execute': 'Выполнить payload',
    'lab.sqli.done': 'Симуляция SQLi завершена',
    'lab.xss.render': 'Рендер в sandbox',
    'lab.csrf.generate': 'Сгенерировать CSRF-сценарий',
    'lab.jwt.analyze': 'Анализировать JWT',
    'lab.headers.analyze': 'Анализировать headers',
    'lab.path.normalize': 'Нормализовать путь',
    'reports.title': 'Генератор отчётов',
    'reports.print': 'Экспорт print-ready отчёта',
    'reports.empty': 'Сессий пока нет. Запустите симуляцию, чтобы наполнить архив отчётов.',
    'vulnerabilities.title': 'База threat intelligence',
    'vulnerabilities.subtitle': 'Фильтруемая база уязвимостей с OWASP, CWE, CVE, CVSS и правовым контекстом.',
    'vulnerabilities.search': 'Поиск по имени, CWE, категории',
    'vulnerabilities.testInLab': 'Тестировать в Lab',
    'vulnerabilities.sort.cvss': 'По CVSS',
    'vulnerabilities.sort.name': 'По имени',
    'vulnerabilities.sort.owasp': 'По OWASP',
    'vulnerabilities.exploitComplexity': 'Сложность эксплуатации',
    'vulnerabilities.cveExamples': 'Примеры CVE',
    'vulnerabilities.allSeverities': 'Все уровни критичности',
    'severity.critical': 'Критическая',
    'severity.high': 'Высокая',
    'severity.medium': 'Средняя',
    'severity.low': 'Низкая',
    'detail.timeToFix': 'Срок исправления',
    'detail.overview': 'Обзор',
    'detail.affectedPlatforms': 'Затронутые платформы',
    'detail.cvssProfile': 'Профиль CVSS',
    'detail.attackFlow': 'Ход атаки',
    'detail.attackerMindset': 'Мышление атакующего',
    'detail.defenderMindset': 'Мышление защитника',
    'detail.codeDiff': 'Сравнение кода',
    'detail.fixChecklist': 'Чеклист исправления',
    'reports.paper': 'Дипломный отчёт',
    'reports.summary': 'Краткое резюме: платформа демонстрирует безопасные browser-only симуляции, устойчивое накопление исследовательских сессий и сравнительный правовой анализ.',
    'reports.notice': 'Правовая оговорка: все эксперименты выполнялись в локальных браузерных симуляциях; реальные production-системы не тестировались.',
    'reports.sessions': 'Записанные лабораторные сессии',
    'lab.csrf.action': 'Адрес действия',
    'lab.csrf.amount': 'Сумма',
    'lab.csrf.samesite': 'Политика SameSite cookie',
    'lab.csrf.tokenValidity': 'Валидность токена',
    'lab.csrf.valid': 'формат корректен',
    'lab.csrf.invalid': 'формат некорректен',
    'legal.title': 'Центр правовой аналитики',
    'owasp.title': 'OWASP Intelligence',
    'about.title': 'Документация проекта',
    'threat.title': 'Студия моделирования угроз',
    'legal.scenarioTitle': 'Симулятор правового сценария',
    'legal.exposure': 'Вероятная правовая экспозиция',
    'legal.precedent': 'Прецедент / контекст',
    'legal.verdict': 'Законно или нет',
    'legal.verdictValue': 'незаконно / высокий риск, достоверность 0.86',
    'legal.timelineTitle': 'Таймлайн ответственного раскрытия',
    'legal.timeline.note':
      'Правомерность зависит от объёма действий, наличия разрешения, соблюдения программы раскрытия и отсутствия выхода за согласованные рамки тестирования.',
    'legal.quizTitle': 'Интерактивный квиз: законно или незаконно?',
    'legal.quizExplanation':
      'Правовой статус зависит от разрешения, допустимого scope и последствий; тестирование production-систем без согласия обычно незаконно.',
    'owasp.trendTitle': 'Изменение рангов по годам',
    'owasp.heatmapTitle': 'Тепловая карта распространённости',
    'owasp.prevalence': 'Распространённость',
    'owasp.detectionDifficulty': 'Сложность обнаружения',
    'owasp.industries': 'Отрасли',
    'owasp.new': 'новый',
    'home.latestResearch': 'Последние исследования',
    'home.opsSummary': 'Оперативная сводка',
    'lab.section.target': 'Цель и конфигурация',
    'lab.section.query': 'Запрос и ответ',
    'lab.section.analysis': 'Анализ',
    'lab.section.payload': 'Конфигурация payload',
    'lab.section.preview': 'Предпросмотр sandbox',
    'lab.section.form': 'Конструктор формы',
    'lab.section.html': 'Вредоносный HTML',
    'lab.section.token': 'Входной токен',
    'lab.section.decoded': 'Декодированный токен',
    'lab.section.generator': 'Генератор и выводы',
    'lab.section.headersInput': 'Ввод заголовков',
    'lab.section.score': 'Оценка',
    'lab.section.pathInput': 'Ввод пути',
    'lab.section.normalized': 'Нормализованный путь',
    'lab.section.fileOutput': 'Содержимое файла',
    'lab.recommendation': 'Рекомендация',
    'lab.legalContext': 'Правовой контекст',
    'lab.simulatedResponse': 'Симулированный ответ',
    'lab.csrf.token': 'CSRF-токен',
    'lab.tab.headers': 'Заголовки',
    'lab.xss.csp': 'CSP включён',
    'lab.xss.distinction': 'Различение',
    'lab.xss.dom': 'DOM-ориентированный сценарий',
    'lab.xss.reflectedStored': 'Вероятен отражённый или сохранённый сценарий в зависимости от контекста хранения.',
    'lab.jwt.algDemo': 'Демонстрация подмены алгоритма',
    'lab.jwt.notAvailable': 'н/д',
    'lab.jwt.active': 'Активен',
    'lab.jwt.expired': 'Истёк',
    'lab.headers.missing': 'Отсутствует',
    'reports.payloads': 'Полезные нагрузки',
    'reports.risk': 'Риск',
    'reports.riskScore': 'Оценка риска',
    'reports.timestamp': 'Временная метка',
    'reports.vulnerability': 'Уязвимость',
    'about.methodology': 'Методология исследования',
    'about.disclaimer': 'Этическая оговорка',
    'about.architecture': 'Схема архитектуры платформы',
    'about.bibliography': 'Библиография',
    'about.arch.ui': 'React UI',
    'about.arch.uiDesc': 'Главная · Лаб · Право',
    'about.arch.sim': 'Симуляторы',
    'about.arch.simDesc': 'SQLi · XSS · JWT · CSRF',
    'about.arch.data': 'Источники данных',
    'about.arch.dataDesc': 'OWASP · CVE · нормы права · localStorage',
    'about.arch.report': 'Отчёты',
    'about.arch.reportDesc': 'Печать · экспорт · артефакты',
    'detail.vulnerable': 'Уязвимый код',
    'detail.secure': 'Безопасный код'
    ,'threat.strideTitle': 'STRIDE workshop'
    ,'threat.attackTreeTitle': 'Построитель дерева атак'
    ,'threat.addNode': 'Добавить узел'
    ,'threat.asset': 'Актив'
    ,'threat.description': 'Описание угрозы'
    ,'threat.controls': 'Текущие меры защиты'
    ,'threat.mitigation': 'Предлагаемая мера снижения риска'
    ,'threat.save': 'Сохранить запись STRIDE'
    ,'threat.newNode': 'Новый узел'
    ,'threat.overallScore': 'Итоговая реализуемость атаки'
    ,'threat.riskMatrix': 'Матрица рисков'
    ,'threat.exportImage': 'Экспорт изображения'
    ,'threat.dreadTitle': 'Калькулятор DREAD'
    ,'threat.dreadScore': 'Оценка DREAD'
    ,'threat.classification': 'Классификация'
    ,'threat.highRisk': 'Высокий риск'
    ,'threat.moderateRisk': 'Средний риск'
    ,'threat.lowRisk': 'Низкий риск'
    ,'threat.damage': 'Ущерб'
    ,'threat.reproducibility': 'Воспроизводимость'
    ,'threat.exploitability': 'Эксплуатируемость'
    ,'threat.affectedUsers': 'Затронутые пользователи'
    ,'threat.discoverability': 'Обнаруживаемость'
    ,'threat.category.spoofing': 'Подмена личности'
    ,'threat.category.tampering': 'Подмена данных'
    ,'threat.category.repudiation': 'Отказ от совершённых действий'
    ,'threat.category.infoDisclosure': 'Раскрытие информации'
    ,'threat.category.dos': 'Отказ в обслуживании'
    ,'threat.category.eop': 'Повышение привилегий'
    ,'threat.rootGoal': 'Компрометация исследовательского портала'
    ,'threat.exploitSqli': 'Эксплуатация SQLi'
    ,'threat.paramQueries': 'Параметризованные запросы'
  },
  en: {
    'nav.dashboard': 'Command Center',
    'nav.lab': 'Lab',
    'nav.vulns': 'Vulnerabilities',
    'nav.threat': 'Threat Model',
    'nav.legal': 'Legal',
    'nav.owasp': 'OWASP',
    'nav.reports': 'Reports',
    'nav.about': 'About',
    'search.placeholder': 'Search vulnerabilities, legal articles, presets',
    'search.label': 'Global Search',
    'topbar.themeHint': 'Research locale',
    'ethics.title': 'Ethics acknowledgment',
    'ethics.body':
      'All simulations run locally in the browser. Using these techniques against real systems without permission may trigger criminal liability. This platform is intended strictly for educational and research use.',
    'ethics.confirm': 'I confirm educational use only',
    'shell.classifiedNode': 'CLASSIFIED RESEARCH NODE',
    'shell.ethicsStamp': 'CLASSIFIED / ETHICS REQUIRED',
    'common.educationalOnly': 'Educational sandbox only',
    'common.localDisclaimer':
      'All simulations run locally in the browser. Using these techniques against real systems without permission may trigger criminal liability.',
    'common.detectedTechnique': 'Detected technique',
    'common.runAt': 'Last execution',
    'common.executed': 'Simulation executed',
    'home.kicker': 'DARKNET RESEARCH LAB / COMMAND CENTER',
    'home.title': 'Analysis and modeling of web application vulnerabilities',
    'home.subtitle':
      'The platform combines technical analysis, attack modeling, reporting, and comparative legal assessment of exploitation consequences.',
    'home.openLab': 'Open laboratory',
    'home.openDb': 'Open threat database',
    'home.stats.vulns': 'Vulnerability classes',
    'home.stats.jurisdictions': 'Legal jurisdictions',
    'home.stats.owasp': 'OWASP reference year',
    'home.features.sim': 'Interactive simulators',
    'home.features.legal': 'Legal analytics',
    'home.features.report': 'Diploma-grade reporting',
    'lab.title': 'Interactive Vulnerability Lab',
    'lab.subtitle':
      'All simulators run locally, persist sessions, and automatically surface attack technique and legal risk.',
    'lab.toast.title': 'Ethical Use Reminder',
    'lab.toast.body': 'The lab performs browser-only simulations. Testing real systems without permission is unlawful.',
    'lab.sqli.execute': 'Execute payload',
    'lab.sqli.done': 'SQLi simulation completed',
    'lab.xss.render': 'Render in sandbox',
    'lab.csrf.generate': 'Generate CSRF scenario',
    'lab.jwt.analyze': 'Analyze JWT',
    'lab.headers.analyze': 'Analyze headers',
    'lab.path.normalize': 'Normalize path',
    'reports.title': 'Report Generator',
    'reports.print': 'Export print-ready report',
    'reports.empty': 'No sessions recorded yet. Run a simulation to populate the report archive.',
    'vulnerabilities.title': 'Threat intelligence database',
    'vulnerabilities.subtitle': 'Filterable database of vulnerabilities with OWASP, CWE, CVE, CVSS, and legal context.',
    'vulnerabilities.search': 'Search by name, CWE, category',
    'vulnerabilities.testInLab': 'Test in Lab',
    'vulnerabilities.sort.cvss': 'By CVSS',
    'vulnerabilities.sort.name': 'By name',
    'vulnerabilities.sort.owasp': 'By OWASP',
    'vulnerabilities.exploitComplexity': 'Exploit complexity',
    'vulnerabilities.cveExamples': 'CVE examples',
    'vulnerabilities.allSeverities': 'All severities',
    'severity.critical': 'Critical',
    'severity.high': 'High',
    'severity.medium': 'Medium',
    'severity.low': 'Low',
    'detail.timeToFix': 'Time to fix',
    'detail.overview': 'Overview',
    'detail.affectedPlatforms': 'Affected platforms',
    'detail.cvssProfile': 'CVSS profile',
    'detail.attackFlow': 'Attack flow',
    'detail.attackerMindset': 'Attacker mindset',
    'detail.defenderMindset': 'Defender mindset',
    'detail.codeDiff': 'Code diff',
    'detail.fixChecklist': 'Fix checklist',
    'reports.paper': 'University diploma report',
    'reports.summary': 'Executive summary: platform demonstrates safe browser-only simulations, persistent research tracking, and comparative legal analysis.',
    'reports.notice': 'Legal notice: all experiments were executed in local browser simulations; no production systems were tested.',
    'reports.sessions': 'Recorded lab sessions',
    'lab.csrf.action': 'Action',
    'lab.csrf.amount': 'Amount',
    'lab.csrf.samesite': 'SameSite cookie policy',
    'lab.csrf.tokenValidity': 'Token validity',
    'lab.csrf.valid': 'format valid',
    'lab.csrf.invalid': 'invalid format',
    'legal.title': 'Legal Intelligence Center',
    'owasp.title': 'OWASP Intelligence',
    'about.title': 'Project Documentation',
    'threat.title': 'Threat Modeling Studio',
    'legal.scenarioTitle': 'Legal scenario simulator',
    'legal.exposure': 'Likely exposure',
    'legal.precedent': 'Precedent / context',
    'legal.verdict': 'Legal or not',
    'legal.verdictValue': 'unlawful / high risk, confidence 0.86',
    'legal.timelineTitle': 'Responsible disclosure timeline',
    'legal.timeline.note':
      'Legality depends on authorization, scope compliance, adherence to disclosure rules, and avoiding actions beyond the agreed testing boundary.',
    'legal.quizTitle': 'Interactive Quiz: lawful or unlawful?',
    'legal.quizExplanation':
      'Legal status depends on authorization, scope, and impact; unauthorized production testing is generally unlawful.',
    'owasp.trendTitle': 'Rank change over years',
    'owasp.heatmapTitle': 'Prevalence heatmap',
    'owasp.prevalence': 'Prevalence',
    'owasp.detectionDifficulty': 'Detection difficulty',
    'owasp.industries': 'Industries',
    'owasp.new': 'new',
    'home.latestResearch': 'Latest research',
    'home.opsSummary': 'Operational summary',
    'lab.section.target': 'Target configuration',
    'lab.section.query': 'Query and response',
    'lab.section.analysis': 'Analysis',
    'lab.section.payload': 'Payload configuration',
    'lab.section.preview': 'Sandbox preview',
    'lab.section.form': 'Form builder',
    'lab.section.html': 'Malicious HTML',
    'lab.section.token': 'Token input',
    'lab.section.decoded': 'Decoded token',
    'lab.section.generator': 'Generator and findings',
    'lab.section.headersInput': 'Header input',
    'lab.section.score': 'Score',
    'lab.section.pathInput': 'Path input',
    'lab.section.normalized': 'Normalized path',
    'lab.section.fileOutput': 'File output',
    'lab.recommendation': 'Recommendation',
    'lab.legalContext': 'Legal context',
    'lab.simulatedResponse': 'Simulated response',
    'lab.csrf.token': 'CSRF token',
    'lab.tab.headers': 'Headers',
    'lab.xss.csp': 'CSP enabled',
    'lab.xss.distinction': 'Distinction',
    'lab.xss.dom': 'DOM-based path',
    'lab.xss.reflectedStored': 'Reflected or stored path likely depending on persistence context.',
    'lab.jwt.algDemo': 'Algorithm confusion demo',
    'lab.jwt.notAvailable': 'n/a',
    'lab.jwt.active': 'Active',
    'lab.jwt.expired': 'Expired',
    'lab.headers.missing': 'Missing',
    'reports.payloads': 'Payloads',
    'reports.risk': 'Risk',
    'reports.riskScore': 'Risk score',
    'reports.timestamp': 'Timestamp',
    'reports.vulnerability': 'Vulnerability',
    'about.methodology': 'Research methodology',
    'about.disclaimer': 'Ethical disclaimer',
    'about.architecture': 'Platform architecture diagram',
    'about.bibliography': 'Bibliography',
    'about.arch.ui': 'React UI',
    'about.arch.uiDesc': 'Dashboard · Lab · Law',
    'about.arch.sim': 'Simulators',
    'about.arch.simDesc': 'SQLi · XSS · JWT · CSRF',
    'about.arch.data': 'Data sources',
    'about.arch.dataDesc': 'OWASP · CVE · law refs · localStorage',
    'about.arch.report': 'Reports',
    'about.arch.reportDesc': 'Print · export · artifacts',
    'detail.vulnerable': 'Vulnerable',
    'detail.secure': 'Secure'
    ,'threat.strideTitle': 'STRIDE workshop'
    ,'threat.attackTreeTitle': 'Attack tree builder'
    ,'threat.addNode': 'Add node'
    ,'threat.asset': 'Asset'
    ,'threat.description': 'Threat description'
    ,'threat.controls': 'Current controls'
    ,'threat.mitigation': 'Proposed mitigation'
    ,'threat.save': 'Save STRIDE entry'
    ,'threat.newNode': 'New node'
    ,'threat.overallScore': 'Overall attack feasibility score'
    ,'threat.riskMatrix': 'Risk matrix'
    ,'threat.exportImage': 'Export image'
    ,'threat.dreadTitle': 'DREAD calculator'
    ,'threat.dreadScore': 'DREAD score'
    ,'threat.classification': 'Classification'
    ,'threat.highRisk': 'High risk'
    ,'threat.moderateRisk': 'Moderate risk'
    ,'threat.lowRisk': 'Low risk'
    ,'threat.damage': 'Damage'
    ,'threat.reproducibility': 'Reproducibility'
    ,'threat.exploitability': 'Exploitability'
    ,'threat.affectedUsers': 'Affected users'
    ,'threat.discoverability': 'Discoverability'
    ,'threat.category.spoofing': 'Spoofing'
    ,'threat.category.tampering': 'Tampering'
    ,'threat.category.repudiation': 'Repudiation'
    ,'threat.category.infoDisclosure': 'Information disclosure'
    ,'threat.category.dos': 'Denial of service'
    ,'threat.category.eop': 'Elevation of privilege'
    ,'threat.rootGoal': 'Compromise research portal'
    ,'threat.exploitSqli': 'Exploit SQLi'
    ,'threat.paramQueries': 'Parameterized queries'
  }
} as const

type MessageKey = keyof typeof messages.ru

interface I18nContextValue {
  locale: Locale
  setLocale: (locale: Locale) => void
  t: (key: MessageKey) => string
}

const I18nContext = createContext<I18nContextValue | null>(null)

export function I18nProvider({ children }: PropsWithChildren) {
  const [locale, setLocale] = useState<Locale>(() => {
    const stored = window.localStorage.getItem('locale')
    return stored === 'en' ? 'en' : 'ru'
  })

  useEffect(() => {
    window.localStorage.setItem('locale', locale)
    document.documentElement.lang = locale
  }, [locale])

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      setLocale,
      t: (key) => messages[locale][key]
    }),
    [locale]
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n() {
  const context = useContext(I18nContext)
  if (!context) {
    throw new Error('useI18n must be used within I18nProvider')
  }
  return context
}

export function LocaleToggle() {
  const { locale, setLocale } = useI18n()

  return (
    <ButtonGroup isAttached size="sm" variant="outline">
      <Button
        onClick={() => setLocale('ru')}
        borderColor="rgba(0,255,178,0.18)"
        bg={locale === 'ru' ? 'rgba(0,255,178,0.08)' : 'transparent'}
        color={locale === 'ru' ? 'brand.300' : 'whiteAlpha.700'}
      >
        RU
      </Button>
      <Button
        onClick={() => setLocale('en')}
        borderColor="rgba(0,255,178,0.18)"
        bg={locale === 'en' ? 'rgba(0,255,178,0.08)' : 'transparent'}
        color={locale === 'en' ? 'brand.300' : 'whiteAlpha.700'}
      >
        EN
      </Button>
    </ButtonGroup>
  )
}
