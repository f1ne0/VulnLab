import type { LegalReference } from '../types'
import type { Locale } from '../i18n'

export interface JurisdictionProfile {
  id: 'RU' | 'UZ' | 'US' | 'EU'
  title: string
  laws: Array<{
    article: string
    title: string
    summary: string
    maxPenalty: string
  }>
  notableCases: Array<{
    name: string
    year: number
    summary: string
  }>
}

export function localizeJurisdictionProfiles(locale: Locale): JurisdictionProfile[] {
  if (locale !== 'ru') {
    return jurisdictionProfiles
  }

  return [
    jurisdictionProfiles[0],
    jurisdictionProfiles[1],
    {
      ...jurisdictionProfiles[2],
      title: 'Соединённые Штаты',
      laws: [
        {
          article: '18 U.S.C. §1030 (CFAA)',
          title: 'Закон о компьютерном мошенничестве и злоупотреблениях',
          summary:
            'Федеральный антихакерский закон США, охватывающий несанкционированный доступ, превышение разрешённых полномочий, причинение ущерба защищённым компьютерам, оборот учётных данных и вымогательство с использованием компьютерных систем.',
          maxPenalty: 'Диапазон наказаний: от штрафов до 10 и более лет лишения свободы в зависимости от умысла, ущерба, рецидива и статуса защищённой системы.'
        },
        {
          article: '18 U.S.C. §1029',
          title: 'Мошенничество и связанные действия с устройствами доступа',
          summary:
            'Применяется в ситуациях, когда после компрометации используются или распространяются похищенные токены, учётные данные, платёжные реквизиты либо идентификаторы аккаунтов.',
          maxPenalty: 'До 10 или 15 лет в зависимости от характера деяния.'
        }
      ],
      notableCases: [
        {
          name: 'United States v. Morris',
          year: 1991,
          summary:
            'Один из ранних прецедентов по CFAA, возникший после Morris Worm; подтвердил, что неосторожный выпуск самораспространяющегося кода может повлечь федеральную уголовную ответственность.'
        },
        {
          name: 'Контекст преследования Aaron Swartz',
          year: 2011,
          summary:
            'Дело JSTOR/MIT часто приводится в академической дискуссии как пример широты CFAA и конфликта между договорными ограничениями и уголовной ответственностью.'
        }
      ]
    },
    {
      ...jurisdictionProfiles[3],
      title: 'Европейский союз',
      laws: [
        {
          article: 'Directive 2013/40/EU',
          title: 'Атаки на информационные системы',
          summary:
            'Обязывает государства-члены криминализовать незаконный доступ, вмешательство в систему, вмешательство в данные и незаконный перехват, а также учитывать отягчающие обстоятельства при масштабных атаках.',
          maxPenalty: 'Не менее 2 лет по базовым составам и не менее 5 лет по тяжким квалифицированным случаям в национальной имплементации.'
        },
        {
          article: 'NIS2 / national criminal laws',
          title: 'Контекст имплементации',
          summary:
            'Хотя NIS2 не является уголовным законом, директива существенно влияет на требования комплаенса, обработку инцидентов и модель управления после нарушения безопасности.',
          maxPenalty: 'Административные и регуляторные последствия зависят от национальной транспозиции.'
        }
      ],
      notableCases: [
        {
          name: 'Преследование за ботнеты и вторжения в странах ЕС',
          year: 2022,
          summary:
            'На практике государства-члены часто сочетают киберуголовные составы с нормами о приватности, телекоммуникациях и мошенничестве, если дело связано с кражей данных или нарушением доступности сервиса.'
        }
      ]
    }
  ]
}

export function localizeLegalReferencesByAttack(locale: Locale): Record<string, LegalReference[]> {
  if (locale !== 'ru') {
    return legalReferencesByAttack
  }

  return {
    sqli: [
      legalReferencesByAttack.sqli[0],
      legalReferencesByAttack.sqli[1],
      {
        ...legalReferencesByAttack.sqli[2],
        title: 'Несанкционированный доступ к базе данных через инъекцию',
        summary: 'Использование инъекции для извлечения информации из защищённого компьютера подпадает под конструкции CFAA о доступе и получении информации.',
        maxPenalty: 'Штрафы и лишение свободы в зависимости от ценности данных, ущерба и умысла.',
        caseReference: 'Практика предъявления обвинений по CFAA в делах о вторжении в веб-приложения.'
      },
      {
        ...legalReferencesByAttack.sqli[3],
        title: 'Незаконный доступ и вмешательство в данные',
        summary: 'Инъекция, позволяющая получить доступ без разрешения или модифицировать данные, затрагивает составы незаконного доступа и вмешательства в данные в национальном праве стран ЕС.',
        maxPenalty: 'Зависит от государства-члена; серьёзные случаи предполагают многолетние сроки.',
        caseReference: 'Национальные имплементации киберуголовного законодательства в ЕС.'
      }
    ],
    xss: [
      legalReferencesByAttack.xss[0],
      legalReferencesByAttack.xss[1],
      {
        ...legalReferencesByAttack.xss[2],
        title: 'Захват сессии через внедрение клиентского скрипта',
        summary: 'Хищение токенов или материалов аутентифицированной сессии может поддерживать теории несанкционированного доступа и ущерба по CFAA и смежным нормам о мошенничестве.',
        maxPenalty: 'Зависит от размера ущерба, статуса защищённой системы и формулы обвинения.',
        caseReference: 'Федеральные дела о захвате аккаунтов и краже учётных данных.'
      },
      {
        ...legalReferencesByAttack.xss[3],
        title: 'Незаконный перехват и неправомерный доступ',
        summary: 'Stored- или reflected-XSS, позволяющий перехватывать учётные данные или идентификаторы сессии, может образовывать состав незаконного доступа или перехвата по национальному праву.',
        maxPenalty: 'Варьируется по странам ЕС.',
        caseReference: 'Пересечение киберуголовного и privacy-регулирования в делах о краже учётных данных.'
      }
    ],
    jwt: [
      legalReferencesByAttack.jwt[0],
      legalReferencesByAttack.jwt[1],
      {
        ...legalReferencesByAttack.jwt[2],
        title: 'Доступ по поддельному токену',
        summary: 'Подделка или изменение токенов аутентификации для доступа к закрытым ресурсам является типовым фактическим составом для применения CFAA.',
        maxPenalty: 'Возможна квалификация как тяжкое деяние при ущербе или повторности.',
        caseReference: 'Злоупотребление токенами иногда инкриминируется вместе с wire fraud.'
      },
      {
        ...legalReferencesByAttack.jwt[3],
        title: 'Обход аутентификации через поддельные claims',
        summary: 'Несанкционированный доступ через изменённые JWT-claims обычно подпадает под состав незаконного доступа в национальном праве государств-членов ЕС.',
        maxPenalty: 'Зависит от юрисдикции конкретного государства-члена.',
        caseReference: 'Киберуголовные составы плюс возможные последствия по GDPR после инцидента.'
      }
    ]
  }
}

export const jurisdictionProfiles: JurisdictionProfile[] = [
  {
    id: 'RU',
    title: 'Российская Федерация',
    laws: [
      {
        article: 'УК РФ ст. 272',
        title: 'Неправомерный доступ к компьютерной информации',
        summary:
          'Криминализует доступ к охраняемой законом компьютерной информации, если это повлекло уничтожение, блокирование, модификацию либо копирование данных.',
        maxPenalty: 'До 2 лет лишения свободы, до 5 лет при квалифицирующих признаках.'
      },
      {
        article: 'УК РФ ст. 273',
        title: 'Создание, использование и распространение вредоносных программ',
        summary:
          'Охватывает разработку, использование и распространение вредоносного ПО, предназначенного для нейтрализации средств защиты либо несанкционированного воздействия на данные.',
        maxPenalty: 'До 4 лет лишения свободы, до 7 лет при тяжких последствиях.'
      },
      {
        article: 'УК РФ ст. 274',
        title: 'Нарушение правил эксплуатации средств хранения, обработки или передачи информации',
        summary:
          'Применяется к лицам, обязанным соблюдать правила эксплуатации ИС, если нарушение повлекло уничтожение, блокирование или модификацию охраняемой информации.',
        maxPenalty: 'До 2 лет лишения свободы, выше при тяжких последствиях.'
      }
    ],
    notableCases: [
      {
        name: 'Приговоры по доступу к банковским системам',
        year: 2021,
        summary:
          'Российская практика по ст. 272 УК РФ традиционно акцентирует фактический ущерб, преодоление механизмов защиты и наличие корыстной либо иной заинтересованности.'
      },
      {
        name: 'Практика по вредоносному ПО',
        year: 2023,
        summary:
          'По ст. 273 УК РФ существенное значение имеет доказательство предназначения ПО для противоправного использования, а не только сам факт разработки.'
      }
    ]
  },
  {
    id: 'UZ',
    title: "O'zbekiston Respublikasi / Республика Узбекистан",
    laws: [
      {
        article: 'УК РУз ст. 278¹',
        title: 'Несанкционированный (неправомерный) доступ к компьютерной информации',
        summary:
          'Криминализует доступ к компьютерной информации, охраняемой законом, если деяние повлекло уничтожение, блокирование, модификацию либо копирование данных. Базовый состав по «компьютерным преступлениям» в УК РУз.',
        maxPenalty: 'Штраф до 100 БРВ либо исправительные работы; при квалифицирующих признаках (группой лиц, с использованием служебного положения, причинение крупного ущерба) — лишение свободы до 5 лет.'
      },
      {
        article: 'УК РУз ст. 278²',
        title: 'Изготовление с целью сбыта либо сбыт и распространение специальных средств для получения неправомерного доступа',
        summary:
          'Применяется к разработке и распространению средств обхода защиты информационных систем, включая вредоносное ПО и эксплойты.',
        maxPenalty: 'Лишение свободы до 5 лет; при тяжких последствиях — выше.'
      },
      {
        article: 'УК РУз ст. 278³',
        title: 'Модификация компьютерной информации',
        summary:
          'Криминализует умышленное изменение защищаемой компьютерной информации, повлёкшее существенные нарушения работы ИС или причинение ущерба.',
        maxPenalty: 'Штраф либо лишение свободы до 5 лет в зависимости от тяжести последствий.'
      },
      {
        article: 'УК РУз ст. 278⁴',
        title: 'Компьютерный саботаж',
        summary:
          'Уничтожение, блокирование, приведение в негодность информации либо программно-технических средств; охватывает DDoS и разрушительные DDL-инъекции при наступлении последствий.',
        maxPenalty: 'Лишение свободы до 5 лет; при тяжких последствиях — до 10 лет.'
      },
      {
        article: 'УК РУз ст. 278⁵',
        title: 'Создание, использование или распространение вредоносных программ',
        summary:
          'Аналог ст. 273 УК РФ: программное обеспечение, предназначенное для несанкционированного воздействия на данные либо нейтрализации защиты.',
        maxPenalty: 'Лишение свободы до 5 лет; при особо тяжких последствиях — до 10 лет.'
      },
      {
        article: 'ЗРУ-547 «О персональных данных»',
        title: 'Защита персональных данных (с изменениями 2021–2023)',
        summary:
          'Устанавливает требования к локализации, согласию субъекта, уведомлению об инцидентах. Нарушение влечёт административную ответственность по КоАО и регуляторные меры со стороны UZINFOCOM/Центра кибербезопасности.',
        maxPenalty: 'Штрафы по КоАО ст. 46² (до 100 БРВ для должностных лиц, выше для юр. лиц), приостановка обработки данных.'
      }
    ],
    notableCases: [
      {
        name: 'Практика Центра кибербезопасности при Госинспекции',
        year: 2023,
        summary:
          'UZCERT/Cyber Security Center регулярно фиксирует расследования по ст. 278¹ УК РУз в отношении доступа к банковским и государственным информационным системам; ключевым фактором является доказательство преодоления защиты и копирования данных.'
      },
      {
        name: 'Дела о вредоносном ПО против банковских клиентов',
        year: 2022,
        summary:
          'Распространение скиммеров и троянов под маркой мобильного банкинга квалифицировалось по совокупности ст. 278⁵ УК РУз и норм о мошенничестве (ст. 168 УК РУз).'
      },
      {
        name: 'Защита персональных данных операторов услуг',
        year: 2023,
        summary:
          'Принятие требований о локализации ПДн в РУз привело к серии регуляторных мер против платформ, не выполнивших требование хранения данных граждан Узбекистана на серверах в стране.'
      }
    ]
  },
  {
    id: 'US',
    title: 'United States',
    laws: [
      {
        article: '18 U.S.C. §1030 (CFAA)',
        title: 'Computer Fraud and Abuse Act',
        summary:
          'Federal anti-hacking statute covering unauthorized access, access exceeding authorization, damage to protected computers, trafficking in access credentials, and extortion involving computers.',
        maxPenalty: 'Ranges from fines to 10+ years depending on intent, damage, prior convictions, and protected systems.'
      },
      {
        article: '18 U.S.C. §1029',
        title: 'Fraud and related activity in connection with access devices',
        summary:
          'Relevant where stolen tokens, credentials, payment data, or account identifiers are used or trafficked after compromise.',
        maxPenalty: 'Up to 10 or 15 years depending on conduct.'
      }
    ],
    notableCases: [
      {
        name: 'United States v. Morris',
        year: 1991,
        summary:
          'Early CFAA precedent arising from the Morris Worm; confirmed that reckless release of self-propagating code can trigger federal criminal liability.'
      },
      {
        name: 'Aaron Swartz prosecution context',
        year: 2011,
        summary:
          'The JSTOR/MIT case is widely cited in academic discussions about the breadth of CFAA and the tension between contractual restrictions and criminal liability.'
      }
    ]
  },
  {
    id: 'EU',
    title: 'European Union',
    laws: [
      {
        article: 'Directive 2013/40/EU',
        title: 'Attacks against information systems',
        summary:
          'Requires Member States to criminalize illegal access, illegal system interference, illegal data interference, and interception, with aggravating circumstances for large-scale attacks.',
        maxPenalty: 'At least 2 years for core offenses; at least 5 years for serious aggravated cases under national implementation.'
      },
      {
        article: 'NIS2 / national criminal laws',
        title: 'Implementation context',
        summary:
          'Although NIS2 is not a criminal statute, it materially affects compliance expectations, incident handling, and governance after a security breach.',
        maxPenalty: 'Administrative and regulatory exposure depends on national transposition.'
      }
    ],
    notableCases: [
      {
        name: 'EU member-state prosecutions for botnet and intrusion offenses',
        year: 2022,
        summary:
          'Member states often combine criminal cybercrime charges with privacy, telecom, and fraud statutes when data theft or service disruption is involved.'
      }
    ]
  }
]

export const legalReferencesByAttack: Record<string, LegalReference[]> = {
  sqli: [
    {
      jurisdiction: 'RU',
      title: 'Неправомерный доступ к данным через уязвимость SQL Injection',
      article: 'УК РФ ст. 272',
      summary: 'Эксплуатация SQLi для обхода аутентификации и чтения таблиц обычно трактуется как неправомерный доступ и копирование компьютерной информации.',
      maxPenalty: 'До 2 лет, выше при тяжких последствиях.',
      caseReference: 'Российская практика по доступу к банковским и корпоративным БД.'
    },
    {
      jurisdiction: 'UZ',
      title: 'Неправомерный доступ к БД через SQL-инъекцию (РУз)',
      article: 'УК РУз ст. 278¹ (+ ст. 278³ при модификации)',
      summary:
        'Использование SQL-инъекции для обхода аутентификации, копирования таблиц либо изменения записей образует состав неправомерного доступа к охраняемой компьютерной информации. При разрушительных stacked-запросах добавляется ст. 278⁴ (компьютерный саботаж).',
      maxPenalty: 'До 5 лет лишения свободы при квалифицирующих признаках (группой лиц, существенный ущерб, государственная или банковская ИС).',
      caseReference: 'Практика Центра кибербезопасности и Генпрокуратуры РУз по инцидентам в банковском секторе и порталах госуслуг.'
    },
    {
      jurisdiction: 'US',
      title: 'Unauthorized database access via injection',
      article: '18 U.S.C. §1030(a)(2)',
      summary: 'Using injection to obtain information from a protected computer fits CFAA access and information-obtaining theories.',
      maxPenalty: 'Fines and imprisonment depending on value, damage, and intent.',
      caseReference: 'CFAA charging practice in web application intrusion cases.'
    },
    {
      jurisdiction: 'EU',
      title: 'Illegal access and data interference',
      article: 'Directive 2013/40/EU, Arts. 3-5',
      summary: 'Injection that enables unauthorized access or data manipulation implicates illegal access and data interference provisions in national law.',
      maxPenalty: 'Member-state dependent; serious cases carry multi-year terms.',
      caseReference: 'National cybercrime implementations across the EU.'
    }
  ],
  xss: [
    {
      jurisdiction: 'RU',
      title: 'Кража сессионных данных через XSS',
      article: 'УК РФ ст. 272',
      summary: 'XSS, используемый для похищения cookie и захвата сессии, рассматривается как неправомерное получение охраняемой информации.',
      maxPenalty: 'До 2 лет и выше при квалифицирующих обстоятельствах.',
      caseReference: 'Практика по несанкционированному доступу к аккаунтам.'
    },
    {
      jurisdiction: 'UZ',
      title: 'Захват сессии через XSS (РУз)',
      article: 'УК РУз ст. 278¹; ЗРУ-547 «О персональных данных»',
      summary:
        'Похищение токенов сессии и cookie через внедрённый клиентский скрипт квалифицируется как неправомерный доступ. Если затронуты персональные данные граждан РУз — добавляется ответственность по КоАО ст. 46² за нарушение требований локализации и защиты ПДн.',
      maxPenalty: 'Лишение свободы до 5 лет (ст. 278¹) и штрафы по КоАО для оператора ПДн.',
      caseReference: 'Регуляторные меры Центра кибербезопасности по делам об утечках в сервисах электронной коммерции.'
    },
    {
      jurisdiction: 'US',
      title: 'Session hijacking through client-side script injection',
      article: '18 U.S.C. §1030',
      summary: 'Theft of tokens or authenticated session material can support unauthorized access and damage theories under CFAA and related fraud statutes.',
      maxPenalty: 'Depends on loss, protected system status, and charging theory.',
      caseReference: 'Federal prosecutions involving account takeover and credential theft.'
    },
    {
      jurisdiction: 'EU',
      title: 'Illegal interception and unlawful access',
      article: 'Directive 2013/40/EU',
      summary: 'Stored or reflected XSS that captures credentials or session identifiers may trigger illegal access or interception offenses under member-state law.',
      maxPenalty: 'Varies by national implementation.',
      caseReference: 'EU cybercrime and privacy overlap in credential theft cases.'
    }
  ],
  jwt: [
    {
      jurisdiction: 'RU',
      title: 'Подделка токенов доступа',
      article: 'УК РФ ст. 272',
      summary: 'Использование скомпрометированных или подделанных JWT для доступа к чужим данным подпадает под неправомерный доступ.',
      maxPenalty: 'До 2 лет, выше при ущербе.',
      caseReference: 'Дела о незаконном использовании учётных данных.'
    },
    {
      jurisdiction: 'UZ',
      title: 'Доступ по поддельному JWT (РУз)',
      article: 'УК РУз ст. 278¹; ст. 168 (мошенничество) при имущественном ущербе',
      summary:
        'Подбор HMAC-секрета или подделка claim-ов JWT для получения доступа к чужим ресурсам — типичный фактический состав ст. 278¹ УК РУз. При получении имущественной выгоды добавляется ст. 168 (мошенничество).',
      maxPenalty: 'До 5 лет (ст. 278¹); до 10 лет при совокупности с мошенничеством и крупным размером.',
      caseReference: 'Расследования по компрометации API-токенов в финтех-сервисах.'
    },
    {
      jurisdiction: 'US',
      title: 'Forged token access',
      article: '18 U.S.C. §1030',
      summary: 'Forging or modifying authentication tokens to access restricted resources is a classic CFAA fact pattern.',
      maxPenalty: 'Potential felony exposure with loss or repeat conduct.',
      caseReference: 'Token abuse charged alongside wire fraud in some cases.'
    },
    {
      jurisdiction: 'EU',
      title: 'Authentication bypass with forged claims',
      article: 'Directive 2013/40/EU',
      summary: 'Unauthorized access via altered JWT claims would generally fit illegal access offenses under national law.',
      maxPenalty: 'Member-state dependent.',
      caseReference: 'Cybercrime offenses plus possible GDPR fallout after breach.'
    }
  ]
}
