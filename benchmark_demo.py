#!/usr/bin/env python3
"""
Порівняльний аналіз ефективності ZK-протоколів.

Магістерська кваліфікаційна робота
Розділ 3.4: Дослідження ефективності ZK-протоколів

Протоколи для порівняння:
- Schnorr Sigma Protocol (ECC-based)
- Groth16 zk-SNARK
- PLONK zk-SNARK

Метрики:
- Час генерації доказу (мс)
- Час верифікації (мс)
- Розмір доказу (байт)

Використання:
    python benchmark_demo.py              # Швидкий тест (10 ітерацій)
    python benchmark_demo.py --full       # Повний тест (100 ітерацій)
    python benchmark_demo.py -n 50        # 50 ітерацій
    python benchmark_demo.py --csv results.csv    # Експорт у CSV
    python benchmark_demo.py --latex table.tex    # Експорт у LaTeX
"""

import sys
import os

# Додати кореневу директорію проєкту
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.benchmarks import ProtocolBenchmark
from src.colors import Colors

C = Colors


def print_header():
    """Заголовок бенчмарку."""
    print()
    print(f"{C.BOLD_CYAN}╔{'═' * 68}╗{C.RESET}")
    print(f"{C.BOLD_CYAN}║{C.BOLD_WHITE}{' ПОРІВНЯЛЬНИЙ АНАЛІЗ ZK-ПРОТОКОЛІВ '.center(68)}{C.BOLD_CYAN}║{C.RESET}")
    print(f"{C.BOLD_CYAN}║{C.DIM}{' Магістерська кваліфікаційна робота '.center(68)}{C.BOLD_CYAN}║{C.RESET}")
    print(f"{C.BOLD_CYAN}╚{'═' * 68}╝{C.RESET}")
    print()
    print(f"{C.BOLD_WHITE}Протоколи для порівняння:{C.RESET}")
    print(f"  {C.BOLD_GREEN}1.{C.RESET} {C.CYAN}Schnorr Sigma Protocol{C.RESET} — інтерактивний доказ на ECC")
    print(f"  {C.BOLD_GREEN}2.{C.RESET} {C.CYAN}Groth16 zk-SNARK{C.RESET} — найменший розмір доказу")
    print(f"  {C.BOLD_GREEN}3.{C.RESET} {C.CYAN}PLONK zk-SNARK{C.RESET} — універсальний trusted setup")
    print()
    print(f"{C.BOLD_WHITE}Тестовий сценарій:{C.RESET} верифікація віку (вік ≥ 18)")
    print(f"{C.DIM}{'-' * 70}{C.RESET}")


def print_methodology():
    """Опис методології дослідження."""
    print()
    print(f"{C.BOLD_CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD_WHITE}{'МЕТОДОЛОГІЯ ДОСЛІДЖЕННЯ'.center(70)}{C.RESET}")
    print(f"{C.BOLD_CYAN}{'═' * 70}{C.RESET}")
    print(f"""
  {C.BOLD_WHITE}Умови експерименту:{C.RESET}

    {C.CYAN}•{C.RESET} Однакові вхідні дані для всіх протоколів
    {C.CYAN}•{C.RESET} Множинні ітерації для статистичної достовірності
    {C.CYAN}•{C.RESET} Вимірювання часу: time.perf_counter() (мс)
    {C.CYAN}•{C.RESET} Верифікація коректності кожного доказу

  {C.BOLD_WHITE}Метрики:{C.RESET}

    {C.CYAN}•{C.RESET} Setup time — час ініціалізації
    {C.CYAN}•{C.RESET} Prove time — час генерації доказу
    {C.CYAN}•{C.RESET} Verify time — час верифікації
    {C.CYAN}•{C.RESET} Proof size — розмір доказу в байтах

  {C.BOLD_WHITE}Статистична обробка:{C.RESET}

    {C.CYAN}•{C.RESET} Mean (середнє значення)
    {C.CYAN}•{C.RESET} Std (стандартне відхилення)
    {C.CYAN}•{C.RESET} Min/Max (екстремальні значення)
""")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Порівняльний аналіз ZK-протоколів',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Приклади використання:
  python benchmark_demo.py              # Швидкий тест (10 ітерацій)
  python benchmark_demo.py --full       # Повний тест (100 ітерацій)
  python benchmark_demo.py -n 50        # 50 ітерацій
  python benchmark_demo.py --csv out.csv --latex out.tex
        """
    )

    parser.add_argument(
        '--iterations', '-n',
        type=int,
        default=10,
        help='Кількість ітерацій (за замовчуванням: 10)'
    )

    parser.add_argument(
        '--quick', '-q',
        action='store_true',
        help='Швидкий тест (5 ітерацій)'
    )

    parser.add_argument(
        '--full', '-f',
        action='store_true',
        help='Повний тест (100 ітерацій)'
    )

    parser.add_argument(
        '--csv',
        type=str,
        metavar='FILE',
        help='Експорт результатів у CSV файл'
    )

    parser.add_argument(
        '--latex',
        type=str,
        metavar='FILE',
        help='Експорт результатів у LaTeX таблицю'
    )

    parser.add_argument(
        '--charts',
        type=str,
        metavar='DIR',
        nargs='?',
        const='charts',
        help='Генерація графіків у директорію (за замовчуванням: charts/)'
    )

    parser.add_argument(
        '--age',
        type=int,
        default=25,
        help='Тестовий вік (private input, за замовчуванням: 25)'
    )

    parser.add_argument(
        '--required-age',
        type=int,
        default=18,
        help='Необхідний вік (public input, за замовчуванням: 18)'
    )

    args = parser.parse_args()

    # Визначення кількості ітерацій
    if args.quick:
        iterations = 5
    elif args.full:
        iterations = 100
    else:
        iterations = args.iterations

    print_header()
    print_methodology()

    # Запуск бенчмарку
    benchmark = ProtocolBenchmark(
        iterations=iterations,
        age=args.age,
        required_age=args.required_age
    )

    try:
        benchmark.run_all()
    except KeyboardInterrupt:
        print(f"\n\n{C.BOLD_YELLOW}Бенчмарк перервано користувачем.{C.RESET}")
        sys.exit(1)

    # Виведення результатів
    benchmark.print_results()
    benchmark.print_ascii_charts()
    benchmark.print_rankings()
    benchmark.print_detailed_stats()

    # Експорт за запитом
    if args.csv:
        benchmark.export_to_csv(args.csv)
        print(f"\n{C.GREEN}✓{C.RESET} Результати експортовано: {args.csv}")

    if args.latex:
        benchmark.export_to_latex(args.latex)
        print(f"{C.GREEN}✓{C.RESET} LaTeX таблиця експортована: {args.latex}")

    if args.charts:
        print(f"\n{C.BOLD_WHITE}Генерація графіків...{C.RESET}")
        benchmark.export_charts(args.charts)

    # Підсумок
    print()
    print(f"{C.BOLD_CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD_WHITE}{'ВИСНОВКИ'.center(70)}{C.RESET}")
    print(f"{C.BOLD_CYAN}{'═' * 70}{C.RESET}")

    results = benchmark.get_summary_dict()

    if 'schnorr' in results and results['schnorr']['iterations'] > 0:
        print(f"\n{C.BOLD_GREEN}1. Schnorr Protocol:{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} {C.BOLD_WHITE}Найшвидший setup{C.RESET} (без trusted setup)")
        print(f"   {C.CYAN}•{C.RESET} Час генерації: {C.BOLD_YELLOW}{results['schnorr']['prove_ms']['mean']:.2f} мс{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Час верифікації: {C.BOLD_YELLOW}{results['schnorr']['verify_ms']['mean']:.2f} мс{C.RESET}")

    if 'groth16' in results and results['groth16']['iterations'] > 0:
        print(f"\n{C.BOLD_GREEN}2. Groth16:{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} {C.BOLD_WHITE}Найменший доказ:{C.RESET} {C.BOLD_MAGENTA}{results['groth16']['proof_size_bytes']:.0f} байт{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Час генерації: {C.BOLD_YELLOW}{results['groth16']['prove_ms']['mean']:.2f} мс{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Час верифікації: {C.BOLD_YELLOW}{results['groth16']['verify_ms']['mean']:.2f} мс{C.RESET}")

    if 'plonk' in results and results['plonk']['iterations'] > 0:
        print(f"\n{C.BOLD_GREEN}3. PLONK:{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} {C.BOLD_WHITE}Універсальний trusted setup{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Час генерації: {C.BOLD_YELLOW}{results['plonk']['prove_ms']['mean']:.2f} мс{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Час верифікації: {C.BOLD_YELLOW}{results['plonk']['verify_ms']['mean']:.2f} мс{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Розмір доказу: {C.BOLD_MAGENTA}{results['plonk']['proof_size_bytes']:.0f} байт{C.RESET}")

    print()
    print(f"{C.BOLD_CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD_WHITE}{'Дослідження завершено'.center(70)}{C.RESET}")
    print(f"{C.BOLD_CYAN}{'═' * 70}{C.RESET}")
    print()


if __name__ == "__main__":
    main()