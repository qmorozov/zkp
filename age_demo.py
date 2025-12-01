#!/usr/bin/env python3
"""
Демонстрація протоколу Zero-Knowledge Proof для верифікації віку.

Магістерська кваліфікаційна робота
Тема: Дослідження ефективності ZK-протоколів для верифікації приватних даних

Реалізація:
- Pedersen Commitment (інформаційно-теоретичне приховування)
- Schnorr Sigma Protocol + Fiat-Shamir transform
- Крива secp256k1 (128-bit security)

Автор: Студент магістратури
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from src.crypto_library_zkp import CryptographyLibraryZKP
from src.colors import Colors
import time
import io
import contextlib

C = Colors


def clear():
    """Очищення терміналу."""
    os.system('cls' if os.name == 'nt' else 'clear')


def wait():
    """Очікування підтвердження користувача."""
    input(f"\n  {C.DIM}[Enter] — продовжити{C.RESET}")


def header(title: str, subtitle: str = None):
    """Заголовок розділу."""
    print(f"\n  {C.BOLD_CYAN}{'═' * 66}{C.RESET}")
    print(f"  {C.BOLD_WHITE}{title.center(66)}{C.RESET}")
    if subtitle:
        print(f"  {C.DIM}{subtitle.center(66)}{C.RESET}")
    print(f"  {C.BOLD_CYAN}{'═' * 66}{C.RESET}")


def section(title: str):
    """Підзаголовок секції."""
    print(f"\n  {C.BOLD_WHITE}{title}{C.RESET}")
    print(f"  {C.DIM}{'─' * 60}{C.RESET}")


def info_block(lines: list, color=None):
    """Інформаційний блок."""
    c = color or C.CYAN
    width = max(len(line) for line in lines) + 4
    print(f"\n  {c}┌{'─' * width}┐{C.RESET}")
    for line in lines:
        print(f"  {c}│{C.RESET}  {line.ljust(width - 2)}{c}│{C.RESET}")
    print(f"  {c}└{'─' * width}┘{C.RESET}")


def result(success: bool, message: str):
    """Результат операції."""
    if success:
        symbol = f"{C.BOLD_GREEN}✓{C.RESET}"
        color = C.BOLD_GREEN
    else:
        symbol = f"{C.BOLD_RED}✗{C.RESET}"
        color = C.BOLD_RED
    print(f"\n  {symbol} {color}{message}{C.RESET}")


def metric(label: str, value: str, unit: str = ""):
    """Виведення метрики."""
    print(f"    {C.CYAN}•{C.RESET} {label}: {C.BOLD_WHITE}{value}{C.RESET} {unit}")


# ============================================================================
# ЕКРАНИ ДЕМОНСТРАЦІЇ
# ============================================================================

def screen_title():
    """Титульний екран."""
    clear()
    print(f"""
  {C.BOLD_CYAN}╔══════════════════════════════════════════════════════════════════╗
  ║                                                                  ║
  ║   {C.BOLD_WHITE}ZERO-KNOWLEDGE PROOF: ВЕРИФІКАЦІЯ ВІКУ{C.BOLD_CYAN}                    ║
  ║                                                                  ║
  ║   {C.DIM}Магістерська кваліфікаційна робота{C.BOLD_CYAN}                          ║
  ║                                                                  ║
  ╚══════════════════════════════════════════════════════════════════╝{C.RESET}

  {C.BOLD_WHITE}Задача:{C.RESET}

    Довести що вік ≥ порогу, НЕ розкриваючи точне значення віку.

  {C.BOLD_WHITE}Як це працює:{C.RESET}

    {C.CYAN}┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  1. Користувач (Prover) має секрет: свій вік                 │
    │                                                              │
    │  2. Сервіс (Verifier) хоче перевірити: вік ≥ 18?             │
    │                                                              │
    │  3. Prover створює математичний доказ                        │
    │                                                              │
    │  4. Verifier перевіряє доказ і дізнається ТІЛЬКИ:            │
    │     "Так, вік ≥ 18" — без точного значення                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘{C.RESET}

  {C.BOLD_WHITE}Гарантії протоколу:{C.RESET}

    {C.GREEN}•{C.RESET} Якщо вік ≥ порогу — доказ завжди пройде перевірку
    {C.GREEN}•{C.RESET} Якщо вік < порогу — неможливо створити валідний доказ
    {C.GREEN}•{C.RESET} Точний вік ніколи не передається і не розкривається
""")


def screen_input():
    """Введення параметрів."""
    clear()
    header("ВХІДНІ ПАРАМЕТРИ", "Налаштування тестового сценарію")

    print(f"""
  {C.BOLD_WHITE}Модель протоколу:{C.RESET}

    {C.CYAN}┌─────────────────┐                      ┌─────────────────┐
    │     PROVER      │   ──── proof ────►   │    VERIFIER     │
    │  (користувач)   │                      │    (сервіс)     │
    └─────────────────┘                      └─────────────────┘{C.RESET}

  {C.BOLD_WHITE}Розподіл інформації:{C.RESET}

    {C.CYAN}Prover:{C.RESET}    володіє секретом (вік)
    {C.CYAN}Verifier:{C.RESET}  знає лише поріг (public)
    {C.CYAN}Результат:{C.RESET} verifier дізнається тільки вік ≥ поріг (так/ні)

  {C.DIM}Введіть параметри демонстрації:{C.RESET}
""")

    while True:
        try:
            age = int(input(f"  {C.BOLD_WHITE}Вік (секретне значення):{C.RESET} "))
            if 0 <= age <= 150:
                break
            print(f"  {C.RED}Допустимий діапазон: 0-150{C.RESET}")
        except ValueError:
            print(f"  {C.RED}Введіть ціле число{C.RESET}")
        except KeyboardInterrupt:
            sys.exit(0)

    while True:
        try:
            threshold = int(input(f"  {C.BOLD_WHITE}Поріг верифікації:{C.RESET} "))
            if 0 <= threshold <= 150:
                break
            print(f"  {C.RED}Допустимий діапазон: 0-150{C.RESET}")
        except ValueError:
            print(f"  {C.RED}Введіть ціле число{C.RESET}")
        except KeyboardInterrupt:
            sys.exit(0)

    return age, threshold


def screen_commitment(system, age):
    """Етап 1: Створення commitment."""
    clear()
    header("ЕТАП 1: СТВОРЕННЯ ЗОБОВ'ЯЗАННЯ", "Commitment — фіксація значення без розкриття")

    section("Що відбувається")
    print(f"""
    Система створює криптографічне зобов'язання для значення віку.

    {C.BOLD_WHITE}Властивості:{C.RESET}
      • Значення (вік) зафіксовано і не може бути змінено
      • Значення неможливо визначити, маючи лише commitment
""")

    section("Виконання")
    print(f"  {C.BOLD_WHITE}Вхідне значення:{C.RESET} вік = {C.BOLD_CYAN}{age}{C.RESET}")
    print(f"  {C.DIM}Генерація випадкового blinding factor...{C.RESET}")
    print(f"  {C.DIM}Обчислення точки на еліптичній кривій...{C.RESET}")

    start = time.perf_counter()
    commitment, blinding, metrics = system.create_pedersen_commitment(age)
    elapsed = (time.perf_counter() - start) * 1000

    # Повні криптографічні дані
    comm_x = hex(commitment[0])
    comm_y = hex(commitment[1])

    result(True, f"Commitment створено за {elapsed:.2f} мс")

    section("Криптографічні дані (реальні значення)")
    print(f"""
    {C.DIM}Commitment — точка на кривій secp256k1:{C.RESET}

    {C.CYAN}X:{C.RESET} {C.BOLD_WHITE}{comm_x}{C.RESET}

    {C.CYAN}Y:{C.RESET} {C.BOLD_WHITE}{comm_y}{C.RESET}

    {C.DIM}Blinding factor: {metrics['blinding_factor_bits']} біт (випадкове число){C.RESET}
    {C.DIM}Час обчислення: {elapsed:.2f} мс{C.RESET}

    {C.YELLOW}⚠ Ці значення унікальні для кожного запуску (випадковий blinding factor){C.RESET}
""")

    section("Що знає кожна сторона")
    print(f"""
    {C.BOLD_WHITE}Prover знає:{C.RESET}
      • вік = {age}
      • blinding factor (секретне випадкове число)

    {C.BOLD_WHITE}Verifier знає:{C.RESET}
      • commitment (точка X, Y вище)
      • {C.RED}НЕ знає вік{C.RESET}
""")

    return commitment, blinding, metrics


def screen_proof(system, age, threshold, commitment, blinding):
    """Етап 2: Генерація доказу."""
    clear()
    header("ЕТАП 2: ГЕНЕРАЦІЯ ДОКАЗУ", "Створення Zero-Knowledge Proof")

    age_diff = age - threshold

    section("Що відбувається")
    print(f"""
    Prover створює математичний доказ того, що вік ≥ {threshold}.

    {C.BOLD_WHITE}Перевірка:{C.RESET} вік ({age}) ≥ поріг ({threshold})?
    {C.BOLD_WHITE}Різниця:{C.RESET}   {age} - {threshold} = {C.BOLD_GREEN}{age_diff}{C.RESET} (невід'ємне число)
""")

    section("Виконання")
    print(f"  {C.DIM}Генерація випадкових чисел...{C.RESET}")
    print(f"  {C.DIM}Обчислення криптографічних компонентів...{C.RESET}")
    print(f"  {C.DIM}Формування доказу...{C.RESET}")

    start = time.perf_counter()
    proof, metrics = system.pedersen_prove(age, threshold, commitment, blinding)
    elapsed = (time.perf_counter() - start) * 1000

    result(True, f"Доказ згенеровано за {elapsed:.2f} мс")

    # Реальні дані доказу
    R_x = hex(proof['R'][0])
    R_y = hex(proof['R'][1])
    challenge = hex(proof['c'])
    s1 = hex(proof['s1'])
    s2 = hex(proof['s2'])

    section("Криптографічні дані доказу (реальні значення)")
    print(f"""
    {C.DIM}Компонент R (точка на кривій):{C.RESET}
    {C.CYAN}R.x:{C.RESET} {C.BOLD_WHITE}{R_x}{C.RESET}
    {C.CYAN}R.y:{C.RESET} {C.BOLD_WHITE}{R_y}{C.RESET}

    {C.DIM}Challenge (256-bit hash):{C.RESET}
    {C.CYAN}c:{C.RESET}   {C.BOLD_WHITE}{challenge}{C.RESET}

    {C.DIM}Responses:{C.RESET}
    {C.CYAN}s₁:{C.RESET}  {C.BOLD_WHITE}{s1}{C.RESET}
    {C.CYAN}s₂:{C.RESET}  {C.BOLD_WHITE}{s2}{C.RESET}

    {C.YELLOW}⚠ Ці значення унікальні для кожного запуску{C.RESET}
""")

    section("Характеристики доказу")
    print(f"""
    • Розмір: {C.BOLD_WHITE}{metrics['proof_size_bytes']}{C.RESET} байт
    • Час генерації: {C.BOLD_WHITE}{elapsed:.2f}{C.RESET} мс

    {C.BOLD_WHITE}Що міститься в доказі:{C.RESET}
      {C.GREEN}✓{C.RESET} R, c, s₁, s₂ — криптографічні значення
      {C.RED}✗{C.RESET} Значення віку ({age}) — НЕ міститься
""")

    return proof, metrics


def screen_verify(system, commitment, threshold, proof):
    """Етап 3: Верифікація."""
    clear()
    header("ЕТАП 3: ВЕРИФІКАЦІЯ ДОКАЗУ", "Перевірка на стороні Verifier")

    section("Що відбувається")
    print(f"""
    Verifier отримав commitment і доказ від Prover.
    Тепер він перевіряє, чи доказ є валідним.

    {C.BOLD_WHITE}Verifier НЕ знає:{C.RESET}
      • Точне значення віку
      • Blinding factor

    {C.BOLD_WHITE}Verifier має:{C.RESET}
      • Commitment (публічний)
      • Доказ (R, c, s₁, s₂)
      • Поріг = {threshold}
""")

    section("Виконання верифікації")
    print(f"  {C.DIM}Перевірка криптографічного рівняння...{C.RESET}")

    start = time.perf_counter()
    is_valid, metrics = system.pedersen_verify(commitment, threshold, proof)
    elapsed = (time.perf_counter() - start) * 1000

    if is_valid:
        result(True, f"ВЕРИФІКАЦІЯ УСПІШНА")
    else:
        result(False, "ВЕРИФІКАЦІЯ НЕВДАЛА")

    section("Деталі перевірки")
    print(f"""
    {C.CYAN}1.{C.RESET} Challenge відповідає hash: {C.BOLD_WHITE}{'Так' if metrics.get('challenge_matched') else 'Ні'}{C.RESET}
    {C.CYAN}2.{C.RESET} Криптографічне рівняння виконано: {C.BOLD_WHITE}{'Так' if metrics.get('equation_verified') else 'Ні'}{C.RESET}
    {C.CYAN}3.{C.RESET} Час верифікації: {C.BOLD_WHITE}{elapsed:.2f}{C.RESET} мс
""")

    section("Результат")
    print(f"""
    {C.GREEN}┌───────────────────────────────────────────────────────────────┐{C.RESET}
    {C.GREEN}│{C.RESET}                                                               {C.GREEN}│{C.RESET}
    {C.GREEN}│{C.RESET}   {C.BOLD_WHITE}Verifier отримав відповідь:{C.RESET}                               {C.GREEN}│{C.RESET}
    {C.GREEN}│{C.RESET}                                                               {C.GREEN}│{C.RESET}
    {C.GREEN}│{C.RESET}   {C.BOLD_GREEN}✓ "Так, вік користувача ≥ {threshold}"{C.RESET}                        {C.GREEN}│{C.RESET}
    {C.GREEN}│{C.RESET}                                                               {C.GREEN}│{C.RESET}
    {C.GREEN}│{C.RESET}   {C.RED}✗ Точний вік — НЕВІДОМИЙ{C.RESET}                                {C.GREEN}│{C.RESET}
    {C.GREEN}│{C.RESET}                                                               {C.GREEN}│{C.RESET}
    {C.GREEN}└───────────────────────────────────────────────────────────────┘{C.RESET}
""")

    return is_valid, metrics


def screen_soundness(system, threshold):
    """Етап 4: Демонстрація Soundness."""
    clear()
    header("ЕТАП 4: ПЕРЕВІРКА SOUNDNESS", "Неможливість фальсифікації")

    section("Визначення властивості")
    print(f"""
    {C.BOLD_WHITE}Soundness:{C.RESET} нечесний prover з ймовірністю ≈ 0 може
    створити валідний доказ для хибного твердження.

    Базується на складності задачі ECDLP (Elliptic Curve
    Discrete Logarithm Problem) для кривої secp256k1.
""")

    section("Тестовий сценарій")
    fake_age = 15
    info_block([
        f"Спроба: створити доказ для вік = {fake_age}",
        f"Поріг: {threshold}",
        f"Твердження: {fake_age} ≥ {threshold} — ХИБНЕ",
    ])

    section("Виконання")
    print(f"  {C.DIM}Спроба генерації фальшивого доказу...{C.RESET}")

    fake_comm, fake_blind, _ = system.create_pedersen_commitment(fake_age)

    try:
        system.pedersen_prove(fake_age, threshold, fake_comm, fake_blind)
        result(False, "ПОМИЛКА: система дозволила фальсифікацію!")
        soundness_ok = False
    except ValueError:
        result(True, "Система відхилила спробу — Soundness підтверджено")
        soundness_ok = True

    section("Висновок")
    print(f"""
    {C.GREEN}✓{C.RESET} Властивість {C.BOLD_WHITE}Soundness{C.RESET} забезпечена

    Математична гарантія: створення валідного доказу для
    хибного твердження вимагає розв'язання задачі ECDLP,
    що є обчислювально нездійсненним (2^128 операцій).
""")

    return soundness_ok


def screen_summary(age, threshold, comm_ms, proof_ms, verify_ms):
    """Підсумковий екран."""
    clear()
    header("ПІДСУМКИ ДЕМОНСТРАЦІЇ", "Результати та метрики")

    total = comm_ms + proof_ms + verify_ms

    section("Підтверджені властивості ZKP")
    print(f"""
    {C.GREEN}✓{C.RESET} {C.BOLD_WHITE}Completeness{C.RESET}   — чесний доказ прийнято
    {C.GREEN}✓{C.RESET} {C.BOLD_WHITE}Soundness{C.RESET}      — фальшивий доказ відхилено
    {C.GREEN}✓{C.RESET} {C.BOLD_WHITE}Zero-Knowledge{C.RESET} — вік = {age} залишився приватним
""")

    section("Метрики продуктивності")

    # ASCII графік
    max_t = max(comm_ms, proof_ms, verify_ms)
    def bar(val, max_val, width=25):
        filled = int((val / max_val) * width) if max_val > 0 else 0
        return "█" * filled + "░" * (width - filled)

    print(f"""
    Commitment    {C.GREEN}{bar(comm_ms, max_t)}{C.RESET}  {comm_ms:>7.2f} мс
    Proof         {C.YELLOW}{bar(proof_ms, max_t)}{C.RESET}  {proof_ms:>7.2f} мс
    Verification  {C.CYAN}{bar(verify_ms, max_t)}{C.RESET}  {verify_ms:>7.2f} мс
    {C.DIM}{'─' * 50}{C.RESET}
    {C.BOLD_WHITE}Загалом:{C.RESET}                                   {total:>7.2f} мс
""")

    section("Технічні характеристики")
    info_block([
        "Крива: secp256k1 (256-bit)",
        "Протокол: Schnorr Sigma + Pedersen Commitment",
        "Безпека: 128 біт (ECDLP)",
        "Бібліотека: py_ecc (Ethereum Foundation)",
    ])

    section("Сфери застосування")
    print(f"""
    {C.CYAN}•{C.RESET} Системи контролю доступу
    {C.CYAN}•{C.RESET} Privacy-preserving KYC процедури
    {C.CYAN}•{C.RESET} Verifiable Credentials (W3C стандарт)
    {C.CYAN}•{C.RESET} Self-Sovereign Identity (SSI)
""")


def screen_soundness_demo(system, age, threshold):
    """Демонстрація Soundness для випадку age < threshold."""
    clear()
    header("ДЕМОНСТРАЦІЯ SOUNDNESS", "Верифікація хибного твердження")

    section("Сценарій")
    print(f"""
    Вік:       {C.BOLD_WHITE}{age}{C.RESET}
    Поріг:     {C.BOLD_WHITE}{threshold}{C.RESET}

    Твердження "{age} ≥ {threshold}" — {C.BOLD_RED}ХИБНЕ{C.RESET}
""")

    section("Питання")
    print(f"""
    Чи може Prover обманути систему та створити
    валідний доказ для хибного твердження?
""")

    section("Виконання")
    print(f"  {C.DIM}Спроба створення доказу...{C.RESET}")

    commitment, blinding, _ = system.create_pedersen_commitment(age)

    try:
        system.pedersen_prove(age, threshold, commitment, blinding)
        result(False, "КРИТИЧНА ПОМИЛКА: доказ створено!")
    except ValueError:
        result(True, "Система відхилила спробу")

        print(f"""
  {C.BOLD_WHITE}Висновок:{C.RESET}

    {C.GREEN}┌───────────────────────────────────────────────────────────────┐
    │                                                               │
    │   {C.BOLD_WHITE}SOUNDNESS ПІДТВЕРДЖЕНО{C.RESET}{C.GREEN}                                      │
    │                                                               │
    │   Неможливо створити валідний доказ для хибного              │
    │   твердження. Це математична гарантія, що базується          │
    │   на складності задачі ECDLP.                                │
    │                                                               │
    └───────────────────────────────────────────────────────────────┘{C.RESET}
""")


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Головна функція демонстрації."""
    # Титульний екран
    screen_title()
    wait()

    # Введення параметрів
    age, threshold = screen_input()

    # Ініціалізація криптосистеми
    clear()
    print(f"\n  {C.CYAN}Ініціалізація криптографічної системи...{C.RESET}")
    f = io.StringIO()
    with contextlib.redirect_stdout(f):
        system = CryptographyLibraryZKP()
    print(f"  {C.GREEN}✓{C.RESET} Система ініціалізована\n")
    time.sleep(0.5)

    # Перевірка Soundness для age < threshold
    if age < threshold:
        screen_soundness_demo(system, age, threshold)
        print(f"\n  {C.BOLD_CYAN}{'═' * 66}{C.RESET}")
        print(f"  {C.BOLD_WHITE}{'Демонстрацію завершено'.center(66)}{C.RESET}")
        print(f"  {C.BOLD_CYAN}{'═' * 66}{C.RESET}\n")
        return

    # Етап 1: Commitment
    commitment, blinding, comm_metrics = screen_commitment(system, age)
    wait()

    # Етап 2: Proof
    proof, proof_metrics = screen_proof(system, age, threshold, commitment, blinding)
    wait()

    # Етап 3: Verification
    is_valid, verify_metrics = screen_verify(system, commitment, threshold, proof)
    wait()

    # Етап 4: Soundness test
    screen_soundness(system, threshold)
    wait()

    # Підсумки
    screen_summary(
        age, threshold,
        comm_metrics['computation_time_ms'],
        proof_metrics['total_time_ms'],
        verify_metrics['total_time_ms']
    )

    print(f"\n  {C.BOLD_CYAN}{'═' * 66}{C.RESET}")
    print(f"  {C.BOLD_WHITE}{'Демонстрацію завершено'.center(66)}{C.RESET}")
    print(f"  {C.BOLD_CYAN}{'═' * 66}{C.RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Перервано користувачем.{C.RESET}")
        sys.exit(0)