# CrossEra Messenger

[![PHP](https://img.shields.io/badge/PHP-7.0%2B-777bb4.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-S60v5%20%7C%20WM6.1%20%7C%20XP%20%7C%20Web-success)]()

**Кросс-платформенный веб-мессенджер**  
Работает на **Symbian S60v5, Windows Mobile 6.1, Windows XP** и любых современных устройствах с браузером.

👉 **[Попробовать демо](https://club2000.atwebpages.com)** 👈

---

## Возможности

| Категория | Что умеет |
|-----------|-----------|
| **Общение** | Личные сообщения, группы, каналы |
| **Мультимедиа** | Передача файлов, отображение картинок в чате |
| **Интерактив** | Реакции , анимированные эмодзи |
| **Социальное** | Аватарки, контакты, онлайн-статусы, избранное |
| **Расширяемость** | Модули с собственным UI (как боты Telegram) |
| **Безопасность** | AES-128 шифрование сообщений на сервере |
| **Интерфейс** | Светлая / тёмная тема |

## Уникальность

CrossEra — **единственный** мессенджер, который полноценно работает на:

| Платформа | Браузер | Статус |
|-----------|---------|--------|
| Symbian S60v5 (Nokia 5800, N97) | WebKit S60 | ✅ Полная поддержка |
| Windows Mobile 6.1 / 6.5 | Internet Explorer Mobile | ✅ Полная поддержка |
| Windows XP | IE8 / Firefox / Chrome | ✅ Полная поддержка |
| Современные ПК / смартфоны | Любой браузер | ✅ Полная поддержка |

## Модульная система

Модули — это «боты» с **собственным интерфейсом** (кнопки, формы, динамическая отрисовка).

Пример модуля каклькулятора:
<?php
// Стартуем сессию, если модуль вызван напрямую, а не из ядра
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Мета-данные для интеграции (если решишь читать их движком)
$mod_info = [
    'name' => 'Calc Lite',
    'version' => '1.0',
    'description' => 'Легкий калькулятор для старых браузеров',
    'compatibility' => 'Opera Mini 8+'
];

// 1. СБОРНАЯ ОБРАБОТКА POST ЗАПРОСОВ (До вывода HTML)
if(isset($_POST['calc_action'])) {
    $display = $_POST['display'] ?? '0';
    $action = $_POST['calc_action'];
    
    switch($action) {
        case 'clear':
            $display = '0';
            break;
        case 'backspace':
            $display = strlen($display) > 1 ? substr($display, 0, -1) : '0';
            break;
        case 'sqrt':
            $val = floatval($display);
            $display = $val >= 0 ? sqrt($val) : 'Ошибка';
            break;
        case '%':
            $display = floatval($display) / 100;
            break;
        case '^':
            // Если в дисплее уже есть знак ^, вычисляем
            if(strpos($display, '^') !== false) {
                $parts = explode('^', $display);
                if(count($parts) == 2) {
                    $display = pow(floatval($parts[0]), floatval($parts[1]));
                }
            } else {
                // Иначе просто дописываем знак степени
                $display .= '^';
            }
            break;
        case 'equals':
            // Безопасное вычисление базовой арифметики
            $expr = str_replace(['×', '÷'], ['*', '/'], $display);
            $expr = preg_replace('/[^0-9+\-*\/\(\)\.]/', '', $expr);
            if (!empty($expr)) {
                @eval('$result = ' . $expr . ';');
                $display = isset($result) && is_numeric($result) ? $result : 'Ошибка';
            }
            break;
        default:
            if(is_numeric($action) || $action === '.' || strpos('+-*/()', $action) !== false) {
                if($display === '0' && is_numeric($action)) {
                    $display = $action;
                } else {
                    $display .= $action;
                }
            }
            break;
    }
    
    if(strlen($display) > 30) $display = substr($display, 0, 30);
    
    $_SESSION['calc_display'] = $display;
    
    // Редирект на самого себя, чтобы не перегружать POST при обновлении страницы в Opera Mini
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Получаем текущее значение дисплея
$display = $_SESSION['calc_display'] ?? '0';
if($display === '') $display = '0';
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Calc Lite</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #002b36; font-family: Arial, sans-serif; font-size: 14px; }
        .calc-box { max-width: 350px; margin: 10px auto; background: #073642; border-radius: 5px; padding: 10px; }
        .screen { background: #002b36; padding: 15px; margin-bottom: 15px; border-radius: 3px; text-align: right; word-break: break-all; }
        .display { color: #93a1a1; font-size: 24px; font-family: 'Courier New', monospace; font-weight: bold; }
        .calc-table { width: 100%; border-collapse: collapse; }
        td.calc-btn { background: #002b36; border: 1px solid #073642; padding: 12px 5px; text-align: center; width: 20%; }
        .btn, .btn-operator, .btn-equals, .btn-clear { 
            width: 100%; background: #002b36; border: none; padding: 12px 5px; 
            color: #839496; font-size: 16px; font-weight: bold; cursor: pointer; 
        }
        .btn-operator { background: #b58900; color: #fff; }
        .btn-equals { background: #2aa198; color: #fff; }
        .btn-clear { background: #dc322f; color: #fff; }
        .info { text-align: center; color: #586e75; font-size: 11px; margin-top: 10px; padding: 5px; }
        @media (max-width: 400px) {
            .btn, .btn-operator, .btn-equals, .btn-clear { padding: 8px 3px; font-size: 14px; }
            .display { font-size: 20px; }
        }
    </style>
</head>
<body>
<div class="calc-box">
    <form method="POST" action="">
        <div class="screen">
            <div class="display"><?php echo htmlspecialchars($display); ?></div>
        </div>
        
        <input type="hidden" name="display" value="<?php echo htmlspecialchars($display); ?>">
        
        <table class="calc-table">
            <tr>
                <td class="calc-btn"><button type="submit" name="calc_action" value="clear" class="btn-clear">C</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="backspace" class="btn">⌫</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="(" class="btn">(</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value=")" class="btn">)</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="/" class="btn-operator">÷</button></td>
            </tr>
            <tr>
                <td class="calc-btn"><button type="submit" name="calc_action" value="7" class="btn">7</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="8" class="btn">8</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="9" class="btn">9</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="*" class="btn-operator">×</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="sqrt" class="btn">√</button></td>
            </tr>
            <tr>
                <td class="calc-btn"><button type="submit" name="calc_action" value="4" class="btn">4</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="5" class="btn">5</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="6" class="btn">6</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="-" class="btn-operator">-</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="^" class="btn">^</button></td>
            </tr>
            <tr>
                <td class="calc-btn"><button type="submit" name="calc_action" value="1" class="btn">1</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="2" class="btn">2</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="3" class="btn">3</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="+" class="btn-operator">+</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="%" class="btn">%</button></td>
            </tr>
            <tr>
                <td class="calc-btn"><button type="submit" name="calc_action" value="0" class="btn">0</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="00" class="btn">00</button></td>
                <td class="calc-btn"><button type="submit" name="calc_action" value="." class="btn">.</button></td>
                <td class="calc-btn" colspan="2"><button type="submit" name="calc_action" value="equals" class="btn-equals">=</button></td>
            </tr>
        </table>
    </form>
    <div class="info">
        Простой калькулятор | Работает без JavaScript
    </div>
</div>
</body>
</html>



Быстрый старт
Установка на свой сервер
bash
git clone https://github.com/Impisre-software/CrossEra-Messenger.git
cd CrossEra-Messenger
# Просто скопируйте файлы в корень вашего веб-сервера
Требования: PHP 7.0+, расширения openssl, session

Или просто используйте нашу веб версию
👉 https://club2000.atwebpages.com 👈

Регистрация за 10 секунд — просто придумайте ID и пароль.

Архитектура (кратко)
Компонент	Технология
Бэкенд	PHP 7+ (файловое хранилище)
Фронтенд	Чистый HTML/CSS (без фреймворков)
Шифрование	AES-128-CTR + HMAC (OpenSSL)
Онлайн-статус	
Модули	
Безопасность
Пароли хранятся с password_hash()

Загрузка файлов проверяется через getimagesize() (блокировка шеллов)

Сообщения шифруются перед записью в файл

Все пути нормализуются через basename() и preg_replace

Разработчик
Impisre Software — независимая команда энтузиастов ретро-совместимости и безопасной коммуникации.

Лицензия
MIT — открытый код для всех.
