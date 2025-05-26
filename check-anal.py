import asyncio
import aiohttp
import pandas as pd
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import logging
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
import json
import re
from urllib.parse import urlparse
import whois
import dns.resolver
from collections import defaultdict
import numpy as np
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

import re

def load_spam_pattern(filepath: str) -> re.Pattern:
    words = []
    with open(filepath, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            words.append(re.escape(line))
    words.sort(key=len, reverse=True)
    pattern = r'(?i)(?:^|\s)(' + '|'.join(words) + r')(?:\s|$)'
    return re.compile(pattern)


# где-то в начале скрипта
spam_pattern = load_spam_pattern('spam_words.txt')

@dataclass
class SEOMetrics:
    """SEO метрики домена"""
    domain_age: Optional[int] = None  # В днях
    registration_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    registrar: Optional[str] = None

    # Wayback метрики
    first_snapshot: Optional[datetime] = None
    last_snapshot: Optional[datetime] = None
    total_snapshots: int = 0
    snapshot_frequency: float = 0.0  # Снимков в месяц

    # История контента
    content_changes: int = 0
    language_changes: List[str] = field(default_factory=list)
    niche_changes: List[str] = field(default_factory=list)

    # Технические метрики
    cms_history: List[str] = field(default_factory=list)
    server_changes: List[str] = field(default_factory=list)
    ssl_history: List[bool] = field(default_factory=list)

    # Спам и качество
    spam_periods: List[Tuple[datetime, datetime]] = field(default_factory=list)
    clean_periods: List[Tuple[datetime, datetime]] = field(default_factory=list)
    spam_ratio: float = 0.0

    # Ссылочный профиль (из Wayback)
    outbound_links_history: Dict[str, int] = field(default_factory=dict)
    internal_links_avg: float = 0.0
    external_links_avg: float = 0.0

    # Дополнительные флаги
    was_hacked: bool = False
    had_malware: bool = False
    was_penalized: bool = False  # Признаки пенализации
    suitable_for_pbn: bool = True
    risk_score: float = 0.0  # 0-100, где 0 - безопасно, 100 - опасно

    # Новые поля из Backorder API
    backorder_price: Optional[float] = None  # price
    backorder_age_years: Optional[int] = None  # old
    backorder_rkn_block: Optional[bool] = None  # rkn
    backorder_judicial: Optional[bool] = None  # judicial
    backorder_links_count: Optional[int] = None  # links



@dataclass
class ContentAnalysis:
    """Анализ контента домена"""
    primary_language: str = "unknown"
    languages_found: Set[str] = field(default_factory=set)
    primary_niche: str = "unknown"
    niches_found: Set[str] = field(default_factory=set)

    # Качество контента
    avg_content_length: float = 0.0
    has_quality_content: bool = False
    content_uniqueness_score: float = 0.0

    # Структура сайта
    page_types: Dict[str, int] = field(default_factory=dict)  # blog, shop, corporate, etc
    has_blog: bool = False
    has_shop: bool = False

    # Медиа
    images_count_avg: float = 0.0
    videos_found: bool = False

    # SEO элементы
    has_meta_descriptions: bool = False
    has_proper_headings: bool = False
    has_schema_markup: bool = False


class PBNDomainAnalyzer:
    """Анализатор доменов для PBN"""

    def __init__(self):
        self.session = None
        self.spam_patterns = self._compile_spam_patterns()
        self.quality_patterns = self._compile_quality_patterns()
        self.cms_patterns = self._compile_cms_patterns()
        self.niche_keywords = self._load_niche_keywords()

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _fetch_backorder_data(self, domain: str, result: Dict):
        """Получает цену, возраст, ссылки, флаги РКН/суд из Backorder.ru API"""
        api_url = (
            f"https://backorder.ru/json/"
            f"?order=desc&domainname={domain}"
            f"&view_all=1&by=hotness&page=1&items=1"
        )
        try:
            async with self.session.get(api_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if isinstance(data, list) and data:
                        entry = data[0]
                        metrics = result['metrics']
                        metrics.backorder_price        = float(entry.get('price', 0))
                        metrics.backorder_age_years    = int(entry.get('old', 0))
                        metrics.backorder_links_count  = int(entry.get('links', 0))
                        metrics.backorder_rkn_block    = bool(entry.get('rkn', False))
                        metrics.backorder_judicial     = bool(entry.get('judicial', False))
        except Exception as e:
            logger.warning(f"Backorder API error for {domain}: {e}")

    def _compile_spam_patterns(self):
        """Компилирует паттерны для определения спама"""
        spam_indicators = [
            # Явный спам
            r'casino|казино|porn|порно|xxx|sex|секс',
            r'viagra|виагра|cialis|сиалис',
            r'gambling|betting|ставки|букмекер',
            r'crypto|bitcoin|биткоин|trading',

            # Признаки взлома
            r'hacked by|defaced by|0wned by',
            r'<script>.*?eval\(|base64_decode|document\.write',
            r'malware|virus|trojan',

            # Китайский спам
            r'[\u4e00-\u9fff]{50,}',  # Много китайских символов подряд

            # Фарма спам
            r'pharmacy|аптека|pills|таблетки|medications'
        ]
        return [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in spam_indicators]

    def _compile_quality_patterns(self):
        """Паттерны для определения качественного контента"""
        return {
            'blog': re.compile(r'blog|article|post|автор|опубликовано|читать далее', re.I),
            'corporate': re.compile(r'about us|о нас|company|компания|services|услуги', re.I),
            'shop': re.compile(r'shop|магазин|cart|корзина|buy|купить|price|цена', re.I),
            'news': re.compile(r'news|новости|press|пресс|latest|последние', re.I),
            'education': re.compile(r'learn|обучение|course|курс|tutorial|руководство', re.I)
        }

    def _compile_cms_patterns(self):
        """Паттерны для определения CMS"""
        return {
            'wordpress': re.compile(r'wp-content|wp-includes|wordpress', re.I),
            'joomla': re.compile(r'joomla|/components/|/modules/', re.I),
            'drupal': re.compile(r'drupal|/sites/default/', re.I),
            'bitrix': re.compile(r'bitrix|/bitrix/', re.I),
            'modx': re.compile(r'modx|/assets/components/', re.I),
            'shopify': re.compile(r'shopify|myshopify\.com', re.I),
            'wix': re.compile(r'wix\.com|wixsite', re.I),
            'tilda': re.compile(r'tilda\.(cc|ws)', re.I),
            'django': re.compile(r'django|csrfmiddlewaretoken', re.I),
            'laravel': re.compile(r'laravel|/public/index\.php', re.I)
        }

    def _load_niche_keywords(self):
        """Загружает ключевые слова для определения ниш"""
        return {
            'finance': ['банк', 'кредит', 'займ', 'инвестиции', 'финансы', 'bank', 'loan', 'investment'],
            'realestate': ['недвижимость', 'квартира', 'дом', 'аренда', 'real estate', 'apartment', 'rent'],
            'health': ['здоровье', 'медицина', 'врач', 'клиника', 'health', 'medical', 'doctor', 'clinic'],
            'tech': ['технологии', 'программирование', 'it', 'software', 'код', 'разработка', 'technology'],
            'education': ['образование', 'обучение', 'курсы', 'школа', 'университет', 'education', 'school'],
            'travel': ['путешествия', 'туризм', 'отель', 'тур', 'travel', 'tourism', 'hotel', 'vacation'],
            'food': ['еда', 'рецепт', 'кулинария', 'ресторан', 'food', 'recipe', 'cooking', 'restaurant'],
            'fashion': ['мода', 'одежда', 'стиль', 'fashion', 'clothes', 'style', 'outfit'],
            'auto': ['авто', 'машина', 'автомобиль', 'car', 'vehicle', 'automotive'],
            'sport': ['спорт', 'фитнес', 'тренировка', 'sport', 'fitness', 'workout', 'gym']
        }

    async def analyze_domain(self, domain: str) -> Dict:
        """Полный анализ домена для PBN"""
        logger.info(f"Начинаем анализ домена: {domain}")

        result = {
            'domain': domain,
            'metrics': SEOMetrics(),
            'content': ContentAnalysis(),
            'wayback_data': {},
            'recommendations': [],
            'warnings': [],
            'pbn_score': 0.0
        }

        # 1. Проверяем WHOIS
        await self._check_whois(domain, result)

        # 1.5. Получаем данные цене и возрасту из Backorder.ru
        await self._fetch_backorder_data(domain, result)

        # 2. Анализируем историю в Wayback Machine
        await self._analyze_wayback_history(domain, result)
        # 3. Проверяем DNS и технические аспекты
        await self._check_dns_records(domain, result)

        # 4. Рассчитываем PBN Score
        self._calculate_pbn_score(result)

        # 5. Генерируем рекомендации
        self._generate_recommendations(result)

        return result

    async def _check_whois(self, domain: str, result: Dict):
        """Проверяет WHOIS информацию"""
        try:
            w = whois.whois(domain)

            if w.creation_date:
                creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                result['metrics'].registration_date = creation
                result['metrics'].domain_age = (datetime.now() - creation).days

            if w.expiration_date:
                expiry = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                result['metrics'].expiry_date = expiry

                # Проверяем, не истекает ли домен скоро
                days_until_expiry = (expiry - datetime.now()).days
                if days_until_expiry < 30:
                    result['warnings'].append(f"Домен истекает через {days_until_expiry} дней!")

            result['metrics'].registrar = w.registrar

        except Exception as e:
            logger.warning(f"Ошибка WHOIS для {domain}: {e}")
            result['warnings'].append("Не удалось получить WHOIS данные")

    async def _check_dns_records(self, domain: str, result: Dict):
        """Проверяет DNS записи"""
        try:
            # Проверяем A записи
            answers = dns.resolver.resolve(domain, 'A')
            result['wayback_data']['current_ips'] = [str(rdata) for rdata in answers]

            # Проверяем MX записи (наличие почты)
            try:
                mx_answers = dns.resolver.resolve(domain, 'MX')
                result['wayback_data']['has_mx'] = len(mx_answers) > 0
            except:
                result['wayback_data']['has_mx'] = False

        except Exception as e:
            logger.warning(f"Ошибка DNS для {domain}: {e}")
            result['warnings'].append("Домен не резолвится или DNS проблемы")
            result['metrics'].suitable_for_pbn = False

    async def _analyze_wayback_history(self, domain: str, result: Dict):
        """Детальный анализ истории в Wayback Machine"""
        try:
            # Получаем все снимки
            api_url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=timestamp,original,mimetype,statuscode,digest"

            async with self.session.get(api_url) as response:
                if response.status != 200:
                    return

                data = await response.json()
                if len(data) <= 1:
                    result['warnings'].append("Нет истории в Wayback Machine")
                    return

                records = data[1:]
                result['metrics'].total_snapshots = len(records)

                # Анализируем временные метки
                timestamps = [datetime.strptime(r[0], "%Y%m%d%H%M%S") for r in records]
                result['metrics'].first_snapshot = min(timestamps)
                result['metrics'].last_snapshot = max(timestamps)

                # Частота снимков
                if len(timestamps) > 1:
                    total_months = (max(timestamps) - min(timestamps)).days / 30
                    result['metrics'].snapshot_frequency = len(timestamps) / total_months if total_months > 0 else 0

                # Группируем снимки по периодам для детального анализа
                await self._analyze_content_periods(domain, records, result)

        except Exception as e:
            logger.error(f"Ошибка анализа Wayback для {domain}: {e}")

    async def _analyze_content_periods(self, domain: str, records: List, result: Dict):
        """Анализирует контент по периодам"""
        # Берём снимки с интервалом для анализа изменений
        snapshots_to_analyze = self._select_representative_snapshots(records, max_snapshots=20)

        content_history = []
        spam_periods = []
        clean_periods = []
        current_period_start = None
        current_period_is_spam = False
        current_period_spam_keywords = set()

        # Сохраняем детальную историю для экспорта
        result['content_history_detailed'] = []

        for i, record in enumerate(snapshots_to_analyze):
            timestamp = record[0]
            url = f"https://web.archive.org/web/{timestamp}/{record[1]}"

            # Анализируем снимок
            analysis = await self._analyze_snapshot_content(url, domain)
            content_history.append({
                'timestamp': datetime.strptime(timestamp, "%Y%m%d%H%M%S"),
                'analysis': analysis
            })

            # Сохраняем детальную информацию для экспорта
            result['content_history_detailed'].append({
                'timestamp': datetime.strptime(timestamp, "%Y%m%d%H%M%S"),
                'url': url,
                'is_spam': analysis.get('is_spam', False),
                'spam_keywords': analysis.get('spam_keywords', []),
                'language': analysis.get('language', 'unknown'),
                'niche': analysis.get('niche', 'unknown'),
                'cms': analysis.get('cms', 'unknown'),
                'content_length': analysis.get('content_length', 0)
            })

            # Определяем периоды спама/чистоты
            is_spam = analysis.get('is_spam', False)

            if i == 0:
                current_period_start = datetime.strptime(timestamp, "%Y%m%d%H%M%S")
                current_period_is_spam = is_spam
                if is_spam:
                    current_period_spam_keywords.update(analysis.get('spam_keywords', []))
            elif is_spam != current_period_is_spam:
                # Период изменился
                period_end = datetime.strptime(timestamp, "%Y%m%d%H%M%S")
                if current_period_is_spam:
                    spam_periods.append((current_period_start, period_end, list(current_period_spam_keywords)))
                else:
                    clean_periods.append((current_period_start, period_end))

                current_period_start = period_end
                current_period_is_spam = is_spam
                current_period_spam_keywords = set(analysis.get('spam_keywords', [])) if is_spam else set()
            elif is_spam:
                # Добавляем новые спам-слова к текущему периоду
                current_period_spam_keywords.update(analysis.get('spam_keywords', []))

        # Сохраняем последний период
        if current_period_start and len(snapshots_to_analyze) > 0:
            last_timestamp = datetime.strptime(snapshots_to_analyze[-1][0], "%Y%m%d%H%M%S")
            if current_period_is_spam:
                spam_periods.append((current_period_start, last_timestamp, list(current_period_spam_keywords)))
            else:
                clean_periods.append((current_period_start, last_timestamp))

        # Обновляем метрики (теперь spam_periods содержит кортежи из 3 элементов)
        result['metrics'].spam_periods = [(start, end) for start, end, _ in spam_periods]
        result['metrics'].clean_periods = clean_periods

        # Сохраняем полную информацию о спам-периодах для экспорта
        result['spam_periods_with_keywords'] = spam_periods

        # Считаем соотношение спама
        total_days = (result['metrics'].last_snapshot - result['metrics'].first_snapshot).days
        spam_days = sum((end - start).days for start, end, _ in spam_periods)
        result['metrics'].spam_ratio = spam_days / total_days if total_days > 0 else 0

        # Анализируем изменения контента
        self._analyze_content_changes(content_history, result)


    async def _analyze_snapshot_content(self, url: str, domain: str) -> Dict:
        """
        Анализирует содержимое одного снимка из Wayback Machine:
        - Загружает страницу
        - Парсит HTML в BeautifulSoup
        - Достаёт чистый текст
        - Ищет спам-слова
        - Считает длину текста и ссылки
        """
        analysis = {
            'is_spam': False,
            'spam_keywords': [],
            'language': 'unknown',
            'niche': 'unknown',
            'cms': 'unknown',
            'content_length': 0,
            'links_internal': 0,
            'links_external': 0,
            'has_quality_signals': False
        }

        try:
            # 1) Скачиваем
            async with self.session.get(url) as response:
                if response.status != 200:
                    return analysis

                # 2) Получаем HTML
                html = await response.text()

            # 3) Парсим его
            soup = BeautifulSoup(html, 'lxml')

            # 4) Достаём чистый текст
            text = soup.get_text(separator=' ', strip=True)
            analysis['content_length'] = len(text)

            # 5) Ищем спам-слова
            found = {m.group(1).strip() for m in spam_pattern.finditer(text)}
            if found:
                analysis['is_spam'] = True
                analysis['spam_keywords'] = list(found)

            # 6) Пример: считаем внутренние и внешние ссылки
            for a in soup.find_all('a', href=True):
                href = a['href'].lower()
                if href.startswith('/') or domain in href:
                    analysis['links_internal'] += 1
                else:
                    analysis['links_external'] += 1

                # Определяем язык (простая эвристика)
                if re.search(r'[а-яА-Я]{10,}', text):
                    analysis['language'] = 'ru'
                elif re.search(r'[a-zA-Z]{10,}', text):
                    analysis['language'] = 'en'

                # Определяем нишу
                text_lower = text.lower()
                for niche, keywords in self.niche_keywords.items():
                    if any(keyword in text_lower for keyword in keywords):
                        analysis['niche'] = niche
                        break

                # Определяем CMS
                html_lower = html.lower()
                for cms, pattern in self.cms_patterns.items():
                    if pattern.search(html_lower):
                        analysis['cms'] = cms
                        break

                # Считаем ссылки
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    if href.startswith('http'):
                        if domain in href:
                            analysis['links_internal'] += 1
                        else:
                            analysis['links_external'] += 1
                    else:
                        analysis['links_internal'] += 1

                # Проверяем качественные сигналы
                if (soup.find('article') or soup.find('main') or
                        len(soup.find_all(['h1', 'h2', 'h3'])) > 3):
                    analysis['has_quality_signals'] = True



        except Exception as e:

            logger.warning(f"Ошибка анализа снимка {url}: {e}")

        return analysis

    def _select_representative_snapshots(self, records: List, max_snapshots: int = 20) -> List:
        """Выбирает репрезентативные снимки для анализа"""
        if len(records) <= max_snapshots:
            return records

        # Берём снимки с равными интервалами
        step = len(records) // max_snapshots
        selected = []

        for i in range(0, len(records), step):
            selected.append(records[i])

        # Обязательно включаем первый и последний
        if records[0] not in selected:
            selected.insert(0, records[0])
        if records[-1] not in selected:
            selected.append(records[-1])

        return selected[:max_snapshots]

    def _analyze_content_changes(self, content_history: List[Dict], result: Dict):
        """Анализирует изменения контента во времени"""
        if not content_history:
            return

        # Собираем уникальные значения
        languages = set()
        niches = set()
        cms_list = []

        for item in content_history:
            analysis = item['analysis']
            if analysis['language'] != 'unknown':
                languages.add(analysis['language'])
            if analysis['niche'] != 'unknown':
                niches.add(analysis['niche'])
            if analysis['cms'] != 'unknown':
                cms_list.append(analysis['cms'])

        # Обновляем результаты
        result['content'].languages_found = languages
        result['content'].primary_language = max(languages, key=lambda x: sum(
            1 for i in content_history if i['analysis']['language'] == x)) if languages else 'unknown'

        result['content'].niches_found = niches
        result['content'].primary_niche = max(niches, key=lambda x: sum(
            1 for i in content_history if i['analysis']['niche'] == x)) if niches else 'unknown'

        result['metrics'].cms_history = list(set(cms_list))

        # Считаем изменения
        prev_lang = None
        prev_niche = None

        for item in content_history:
            analysis = item['analysis']

            if prev_lang and prev_lang != analysis['language'] and analysis['language'] != 'unknown':
                result['metrics'].language_changes.append(f"{prev_lang} -> {analysis['language']}")
            prev_lang = analysis['language']

            if prev_niche and prev_niche != analysis['niche'] and analysis['niche'] != 'unknown':
                result['metrics'].niche_changes.append(f"{prev_niche} -> {analysis['niche']}")
            prev_niche = analysis['niche']

        # Средние показатели
        result['content'].avg_content_length = np.mean([i['analysis']['content_length'] for i in content_history])
        result['metrics'].internal_links_avg = np.mean([i['analysis']['links_internal'] for i in content_history])
        result['metrics'].external_links_avg = np.mean([i['analysis']['links_external'] for i in content_history])

    def _calculate_pbn_score(self, result: Dict):
        """Рассчитывает PBN Score"""
        score = 100.0

        metrics = result['metrics']
        content = result['content']

        # Возраст домена (чем старше, тем лучше)
        if metrics.domain_age:
            if metrics.domain_age < 365:  # Меньше года
                score -= 20
            elif metrics.domain_age < 730:  # Меньше 2 лет
                score -= 10
        else:
            score -= 15

        # История в Wayback
        if metrics.total_snapshots < 10:
            score -= 15
        elif metrics.total_snapshots < 50:
            score -= 5

        # Спам соотношение
        if metrics.spam_ratio > 0.5:  # Больше половины времени был спамом
            score -= 40
        elif metrics.spam_ratio > 0.2:
            score -= 20
        elif metrics.spam_ratio > 0.1:
            score -= 10

        # Изменения ниши
        if len(metrics.niche_changes) > 2:
            score -= 15
        elif len(metrics.niche_changes) > 1:
            score -= 5

        # Изменения языка
        if len(metrics.language_changes) > 1:
            score -= 10

        # Частота обновлений
        if metrics.snapshot_frequency < 0.5:  # Меньше 1 снимка в 2 месяца
            score -= 10

        # Последняя активность
        if metrics.last_snapshot:
            days_since_last = (datetime.now() - metrics.last_snapshot).days
            if days_since_last > 365:  # Больше года не обновлялся
                score -= 15
            elif days_since_last > 180:
                score -= 5

        # Качество контента
        if content.avg_content_length < 500:
            score -= 10

        # Технические проблемы
        if not result['wayback_data'].get('current_ips'):
            score -= 30  # Домен не резолвится

        # Ограничиваем минимальный счёт
        result['pbn_score'] = max(0, score)

        # Определяем пригодность
        result['metrics'].suitable_for_pbn = score >= 60
        result['metrics'].risk_score = 100 - score

    def _generate_recommendations(self, result: Dict):
        """Генерирует рекомендации"""
        score = result['pbn_score']
        metrics = result['metrics']

        if score >= 80:
            result['recommendations'].append("✅ Отличный кандидат для PBN")
            result['recommendations'].append("Рекомендуется к покупке")
        elif score >= 60:
            result['recommendations'].append("⚠️ Хороший кандидат с небольшими рисками")
            result['recommendations'].append("Требуется дополнительная проверка")
        else:
            result['recommendations'].append("❌ Высокий риск для PBN")
            result['recommendations'].append("Не рекомендуется к покупке")

        # Специфичные рекомендации
        if metrics.spam_ratio > 0.1:
            result['recommendations'].append(f"⚠️ Обнаружены периоды спама ({metrics.spam_ratio * 100:.1f}% времени)")
            result['recommendations'].append("Проверьте через Ahrefs/Majestic на наличие плохих ссылок")

        if len(metrics.niche_changes) > 0:
            result['recommendations'].append(f"📊 Домен менял тематику {len(metrics.niche_changes)} раз")
            result['recommendations'].append("Убедитесь, что текущая тематика соответствует вашим целям")

        if metrics.domain_age and metrics.domain_age > 1825:  # 5 лет
            result['recommendations'].append("👍 Возраст домена > 5 лет - хороший траст")

        if metrics.last_snapshot:
            days_inactive = (datetime.now() - metrics.last_snapshot).days
            if days_inactive > 180:
                result['recommendations'].append(f"⏰ Домен неактивен {days_inactive} дней")
                result['recommendations'].append("Проверьте индексацию в Google")

        if len(metrics.cms_history) > 0:
            result['recommendations'].append(f"🔧 Использовались CMS: {', '.join(metrics.cms_history)}")

        # Проверки для PBN
        if metrics.external_links_avg > 20:
            result['recommendations'].append(
                "🔗 Много исходящих ссылок - возможно, уже использовался для продажи ссылок")

        if not result['wayback_data'].get('has_mx', True):
            result['recommendations'].append("📧 Отсутствуют MX записи - настройте почту после покупки")
# загружаем спам-паттерн один раз
        self.spam_pattern = load_spam_pattern('spam_words.txt')
        # больше не нужен self.spam_patterns

class PBNBulkAnalyzer:
    """Массовый анализатор доменов для PBN"""

    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def analyze_domains(self, domains: List[str], output_file: str = "pbn_analysis.xlsx"):
        """Анализирует список доменов"""
        results = []

        async with PBNDomainAnalyzer() as analyzer:
            tasks = []

            for domain in domains:
                task = self._analyze_with_semaphore(analyzer, domain)
                tasks.append(task)

            # Выполняем с прогресс-баром
            for i, task in enumerate(asyncio.as_completed(tasks)):
                result = await task
                results.append(result)
                logger.info(f"Обработано {i + 1}/{len(domains)} доменов")

        # Экспортируем результаты
        self._export_results(results, output_file)

        return results

    async def _analyze_with_semaphore(self, analyzer: PBNDomainAnalyzer, domain: str):
        """Анализирует домен с ограничением параллельности"""
        async with self.semaphore:
            try:
                return await analyzer.analyze_domain(domain)
            except Exception as e:
                logger.error(f"Критическая ошибка для {domain}: {e}")
                return {
                    'domain': domain,
                    'error': str(e),
                    'pbn_score': 0,
                    'metrics': SEOMetrics(),
                    'content': ContentAnalysis()
                }

    def _export_results(self, results: List[Dict], output_file: str):
        """Экспортирует результаты в Excel с несколькими листами"""
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            # Основная сводка
            summary_data = []
            for r in results:
                summary_data.append({
                    'Домен': r['domain'],
                    'PBN Score': f"{r['pbn_score']:.1f}",
                    'Подходит для PBN': '✅' if r['metrics'].suitable_for_pbn else '❌',
                    'Возраст (дней)': r['metrics'].domain_age or 'N/A',
                    'Спам %': f"{r['metrics'].spam_ratio * 100:.1f}%",
                    'Снимков в Wayback': r['metrics'].total_snapshots,
                    'Основная тематика': r['content'].primary_niche,
                    'Основной язык': r['content'].primary_language,
                    'Риск': f"{r['metrics'].risk_score:.1f}",
                    'Цена Backorder': r['metrics'].backorder_price or 'N/A',
                    'Возраст (лет)': r['metrics'].backorder_age_years or 'N/A',
                    'Ссылки (Backorder)': r['metrics'].backorder_links_count or 'N/A',
                    'Заблокирован РКН': 'Да' if r['metrics'].backorder_rkn_block else 'Нет',
                    'Судебный домен': 'Да' if r['metrics'].backorder_judicial else 'Нет',
                    'Рекомендация': r['recommendations'][0] if r['recommendations'] else 'Нет данных'
                })

            df_summary = pd.DataFrame(summary_data)
            df_summary = df_summary.sort_values('PBN Score', ascending=False)
            df_summary.to_excel(writer, sheet_name='Сводка', index=False)

            # Детальный анализ
            detailed_data = []
            for r in results:
                detailed_data.append({
                    'Домен': r['domain'],
                    'Дата регистрации': r['metrics'].registration_date.strftime('%Y-%m-%d') if r[
                        'metrics'].registration_date else 'N/A',
                    'Дата истечения': r['metrics'].expiry_date.strftime('%Y-%m-%d') if r[
                        'metrics'].expiry_date else 'N/A',
                    'Регистратор': r['metrics'].registrar or 'N/A',
                    'Первый снимок': r['metrics'].first_snapshot.strftime('%Y-%m-%d') if r[
                        'metrics'].first_snapshot else 'N/A',
                    'Последний снимок': r['metrics'].last_snapshot.strftime('%Y-%m-%d') if r[
                        'metrics'].last_snapshot else 'N/A',
                    'Частота снимков/мес': f"{r['metrics'].snapshot_frequency:.2f}",
                    'Смена тематик': len(r['metrics'].niche_changes),
                    'Смена языков': len(r['metrics'].language_changes),
                    'История CMS': ', '.join(r['metrics'].cms_history) if r['metrics'].cms_history else 'N/A',
                    'Цена Backorder': r['metrics'].backorder_price or 'N/A',
                    'Возраст (лет)': r['metrics'].backorder_age_years or 'N/A',
                    'Ссылки (Backorder)': r['metrics'].backorder_links_count or 'N/A',
                    'Заблокирован РКН': 'Да' if r['metrics'].backorder_rkn_block else 'Нет',
                    'Судебный домен': 'Да' if r['metrics'].backorder_judicial else 'Нет',
                    'Ср. длина контента': f"{r['content'].avg_content_length:.0f}",
                    'Ср. внутр. ссылок': f"{r['metrics'].internal_links_avg:.1f}",
                    'Ср. внешн. ссылок': f"{r['metrics'].external_links_avg:.1f}"
                })

            df_detailed = pd.DataFrame(detailed_data)
            df_detailed.to_excel(writer, sheet_name='Детальный анализ', index=False)

            # История спама
            spam_data = []
            for r in results:
                # Используем расширенную информацию о спам-периодах
                if 'spam_periods_with_keywords' in r and r['spam_periods_with_keywords']:
                    for start, end, keywords in r['spam_periods_with_keywords']:
                        spam_data.append({
                            'Домен': r['domain'],
                            'Тип': 'Спам',
                            'Начало': start.strftime('%Y-%m-%d'),
                            'Конец': end.strftime('%Y-%m-%d'),
                            'Длительность (дней)': (end - start).days,
                            'Найденные спам-слова': ', '.join(keywords[:10]) if keywords else 'N/A',  # Первые 10 слов
                            'Всего спам-слов': len(keywords)
                        })
                if r['metrics'].clean_periods:
                    for start, end in r['metrics'].clean_periods:
                        spam_data.append({
                            'Домен': r['domain'],
                            'Тип': 'Чистый',
                            'Начало': start.strftime('%Y-%m-%d'),
                            'Конец': end.strftime('%Y-%m-%d'),
                            'Длительность (дней)': (end - start).days,
                            'Найденные спам-слова': '',
                            'Всего спам-слов': 0
                        })

            if spam_data:
                df_spam = pd.DataFrame(spam_data)
                df_spam = df_spam.sort_values(['Домен', 'Начало'])
                df_spam.to_excel(writer, sheet_name='История контента', index=False)

            # Добавляем детальную историю снимков
            if any('content_history_detailed' in r for r in results):
                snapshot_data = []
                for r in results:
                    if 'content_history_detailed' in r:
                        for snapshot in r['content_history_detailed']:
                            snapshot_data.append({
                                'Домен': r['domain'],
                                'Дата снимка': snapshot['timestamp'].strftime('%Y-%m-%d %H:%M'),
                                'URL снимка': snapshot['url'],
                                'Обнаружен спам': 'Да' if snapshot['is_spam'] else 'Нет',
                                'Спам-слова': ', '.join(snapshot['spam_keywords'][:5]) if snapshot[
                                    'spam_keywords'] else '',
                                'Язык': snapshot['language'],
                                'Тематика': snapshot['niche'],
                                'CMS': snapshot['cms'],
                                'Размер контента': snapshot['content_length']
                            })

                if snapshot_data:
                    df_snapshots = pd.DataFrame(snapshot_data)
                    df_snapshots.to_excel(writer, sheet_name='Детали снимков', index=False)

            # Рекомендации
            recommendations_data = []
            for r in results:
                for rec in r['recommendations']:
                    recommendations_data.append({
                        'Домен': r['domain'],
                        'PBN Score': f"{r['pbn_score']:.1f}",
                        'Рекомендация': rec
                    })
                for warning in r.get('warnings', []):
                    recommendations_data.append({
                        'Домен': r['domain'],
                        'PBN Score': f"{r['pbn_score']:.1f}",
                        'Рекомендация': f"⚠️ {warning}"
                    })

            if recommendations_data:
                df_rec = pd.DataFrame(recommendations_data)
                df_rec.to_excel(writer, sheet_name='Рекомендации', index=False)

            # Топ кандидаты для PBN
            top_candidates = [r for r in results if r['pbn_score'] >= 70]
            if top_candidates:
                top_data = []
                for r in sorted(top_candidates, key=lambda x: x['pbn_score'], reverse=True)[:20]:
                    top_data.append({
                        'Домен': r['domain'],
                        'PBN Score': f"{r['pbn_score']:.1f}",
                        'Возраст (лет)': f"{(r['metrics'].domain_age or 0) / 365:.1f}",
                        'Тематика': r['content'].primary_niche,
                        'Причины выбора': ' | '.join(r['recommendations'][:2])
                    })

                df_top = pd.DataFrame(top_data)
                df_top.to_excel(writer, sheet_name='ТОП для PBN', index=False)

        logger.info(f"Результаты сохранены в {output_file}")


# Дополнительные утилиты для SEO

class BacklinkChecker:
    """Проверка обратных ссылок через Wayback (базовая версия)"""

    @staticmethod
    async def check_domain_mentions(domain: str, session: aiohttp.ClientSession) -> Dict:
        """Ищет упоминания домена в Wayback"""
        # Ищем страницы, которые ссылались на домен
        api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&limit=100"

        try:
            async with session.get(api_url) as response:
                if response.status == 200:
                    data = await response.json()
                    if len(data) > 1:
                        return {
                            'mentions_count': len(data) - 1,
                            'unique_domains': len(set(urlparse(r[1]).netloc for r in data[1:]))
                        }
        except:
            pass

        return {'mentions_count': 0, 'unique_domains': 0}


class DomainMetricsExporter:
    """Экспорт метрик в различные форматы"""

    @staticmethod
    def export_for_ahrefs_import(results: List[Dict], filename: str = "domains_for_ahrefs.txt"):
        """Экспортирует домены для массовой проверки в Ahrefs"""
        domains = [r['domain'] for r in results if r['pbn_score'] >= 60]

        with open(filename, 'w') as f:
            f.write('\n'.join(domains))

        logger.info(f"Экспортировано {len(domains)} доменов в {filename}")

    @staticmethod
    def export_monitoring_list(results: List[Dict], filename: str = "domains_monitoring.json"):
        """Создает список для мониторинга доменов"""
        monitoring = []

        for r in results:
            if r['pbn_score'] >= 50:
                monitoring.append({
                    'domain': r['domain'],
                    'score': r['pbn_score'],
                    'expiry_date': r['metrics'].expiry_date.isoformat() if r['metrics'].expiry_date else None,
                    'check_priority': 'high' if r['pbn_score'] >= 80 else 'medium'
                })

        with open(filename, 'w') as f:
            json.dump(monitoring, f, indent=2)

        logger.info(f"Создан список мониторинга: {filename}")


# Основная функция
async def main():
    """Пример использования"""

    # Загружаем домены
    with open('outgoing_domains1.txt', 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    # Фильтруем только уникальные домены
    domains = list(set(domains))
    logger.info(f"Загружено {len(domains)} уникальных доменов")

    # Анализируем
    analyzer = PBNBulkAnalyzer(max_concurrent=5)
    results = await analyzer.analyze_domains(domains, output_file="pbn_analysis.xlsx")

    # Экспортируем дополнительные данные
    DomainMetricsExporter.export_for_ahrefs_import(results)
    DomainMetricsExporter.export_monitoring_list(results)

    # Выводим статистику
    suitable_count = sum(1 for r in results if r['metrics'].suitable_for_pbn)
    top_count = sum(1 for r in results if r['pbn_score'] >= 80)

    print(f"\n📊 СТАТИСТИКА АНАЛИЗА:")
    print(f"Всего проанализировано: {len(results)} доменов")
    print(f"Подходят для PBN: {suitable_count} ({suitable_count / len(results) * 100:.1f}%)")
    print(f"Отличные кандидаты (80+): {top_count}")
    print(f"\nРезультаты сохранены в pbn_analysis.xlsx")


if __name__ == "__main__":
    # Установить необходимые пакеты:
    # pip install aiohttp pandas beautifulsoup4 lxml python-whois dnspython numpy openpyxl pyahocorasick

    asyncio.run(main())