#!/usr/bin/env python3
"""
Security Automation Tools for SOC Operations
=============================================

Main entry point for the security automation suite.
Demonstrates log parsing, anomaly detection, threat intelligence
enrichment, automated response, and report generation.

Usage:
    python main.py --demo              # Run demo with sample data
    python main.py --parse <file>      # Parse a log file
    python main.py --generate-samples  # Generate sample logs
    python main.py --help              # Show help
"""

import argparse
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.log_parser import LogParser, EventNormalizer
from src.detection import AnomalyDetector, RuleEngine
from src.threat_intel import EventEnricher, ThreatIntelManager
from src.response import ResponseOrchestrator
from src.reporting import ReportGenerator
from src.utils import setup_logger, load_yaml_config


def run_demo(config_path: str = "config/config.yaml"):
    """
    Run a demonstration of all security automation tools.
    
    Shows:
    1. Sample log generation
    2. Log parsing and normalization
    3. Anomaly detection
    4. Threat intelligence enrichment
    5. Automated response (dry run)
    6. Report generation
    """
    logger = setup_logger("soc_automation", level="INFO")
    
    print("\n" + "=" * 60)
    print("🛡️  SECURITY AUTOMATION TOOLS - DEMONSTRATION")
    print("=" * 60)
    
    # Load configuration
    print("\n📋 Loading configuration...")
    try:
        config = load_yaml_config(config_path)
        print(f"   ✓ Configuration loaded from {config_path}")
    except FileNotFoundError:
        print(f"   ⚠ Config not found, using defaults")
        config = {}
    
    # Generate sample logs if not present
    print("\n📝 Checking sample logs...")
    sample_dir = Path("data/sample_logs")
    if not sample_dir.exists() or not list(sample_dir.glob("*.log")):
        print("   Generating sample logs...")
        from data.sample_logs.generate_samples import save_sample_logs
        save_sample_logs()
        print("   ✓ Sample logs generated")
    else:
        print("   ✓ Sample logs found")
    
    # Initialize components
    print("\n🔧 Initializing components...")
    
    parser = LogParser()
    normalizer = EventNormalizer()
    detector = AnomalyDetector(config.get('detection', {}).get('thresholds', {}))
    
    ti_manager = ThreatIntelManager(config.get('threat_intel', {}))
    enricher = EventEnricher(ti_manager=ti_manager, config=config.get('threat_intel', {}))
    
    orchestrator = ResponseOrchestrator({
        'auto_response_enabled': True,
        'dry_run': True  # Safe mode for demo
    })
    
    report_gen = ReportGenerator({'output_dir': 'reports'})
    
    print("   ✓ All components initialized")
    
    # Process logs
    print("\n📊 Processing security logs...")
    all_events = []
    
    log_files = [
        ("data/sample_logs/firewall.log", "syslog"),
        ("data/sample_logs/auth.json", "json"),
        ("data/sample_logs/access.csv", "csv"),
    ]
    
    for log_file, format_hint in log_files:
        if Path(log_file).exists():
            print(f"\n   📄 Parsing {log_file}...")
            
            for entry in parser.parse_file(log_file, format_hint):
                if entry.is_valid:
                    event = normalizer.normalize(entry)
                    all_events.append(event)
            
            stats = parser.get_stats()
            print(f"      Parsed: {stats['success']} entries")
            parser.reset_stats()
    
    print(f"\n   ✓ Total events normalized: {len(all_events)}")
    
    # Run detection
    print("\n🔍 Running anomaly detection...")
    all_alerts = []
    
    for event in all_events:
        alerts = detector.process_event(event)
        all_alerts.extend(alerts)
    
    detection_stats = detector.get_stats()
    print(f"   Events processed: {detection_stats['events_processed']}")
    print(f"   Alerts generated: {detection_stats['alerts_generated']}")
    
    if all_alerts:
        print("\n   📢 Alert Summary:")
        for alert in all_alerts[:5]:  # Show first 5
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(alert.severity.value, '⚪')
            print(f"      {severity_emoji} [{alert.severity.value.upper()}] {alert.title}")
    
    # Enrich with threat intelligence
    print("\n🔎 Enriching events with Threat Intelligence...")
    ti_matches = 0
    
    for event in all_events:
        result = enricher.enrich(event)
        if result.enriched:
            ti_matches += 1
    
    enricher_stats = enricher.get_stats()
    print(f"   Events enriched: {enricher_stats['events_enriched']}")
    print(f"   TI matches found: {enricher_stats['events_with_matches']}")
    
    # Run automated response (dry run)
    print("\n⚡ Processing automated responses (DRY RUN)...")
    response_count = 0
    
    for alert in all_alerts:
        executions = orchestrator.process_alert(alert)
        response_count += len(executions)
    
    orch_stats = orchestrator.get_stats()
    print(f"   Playbook executions: {orch_stats['total_executions']}")
    print(f"   Mode: {'DRY RUN' if orch_stats['dry_run'] else 'LIVE'}")
    
    # Generate report
    print("\n📝 Generating security report...")
    report = report_gen.generate_report(
        alerts=all_alerts,
        title="SOC Automation Demo Report",
        events_count=len(all_events)
    )
    
    html_path = report_gen.save_html(report)
    json_path = report_gen.save_json(report)
    
    print(f"   ✓ HTML report: {html_path}")
    print(f"   ✓ JSON report: {json_path}")
    
    # Print executive summary
    print("\n" + "=" * 60)
    print(report_gen.generate_executive_summary(report))
    print("=" * 60)
    
    print("\n✅ Demonstration complete!")
    print(f"   View the HTML report at: {html_path.absolute()}")
    
    return 0


def parse_log_file(file_path: str, format_hint: str = None):
    """Parse and analyze a log file."""
    logger = setup_logger("soc_automation", level="INFO")
    
    print(f"\n📄 Parsing: {file_path}")
    
    parser = LogParser()
    normalizer = EventNormalizer()
    
    events = []
    for entry in parser.parse_file(file_path, format_hint):
        if entry.is_valid:
            event = normalizer.normalize(entry)
            events.append(event)
    
    stats = parser.get_stats()
    norm_stats = normalizer.get_stats()
    
    print(f"\n📊 Results:")
    print(f"   Total lines: {stats['total']}")
    print(f"   Parsed successfully: {stats['success']}")
    print(f"   Parse failures: {stats['failed']}")
    print(f"\n   Events by type:")
    for event_type, count in norm_stats['by_type'].items():
        print(f"      {event_type}: {count}")
    
    return 0


def generate_samples():
    """Generate sample log files."""
    from data.sample_logs.generate_samples import save_sample_logs
    save_sample_logs()
    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Security Automation Tools for SOC Operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo                   Run demonstration
  python main.py --parse /var/log/auth.log  Parse a log file
  python main.py --generate-samples       Generate sample logs
        """
    )
    
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run demonstration with sample data'
    )
    
    parser.add_argument(
        '--parse',
        metavar='FILE',
        help='Parse and analyze a log file'
    )
    
    parser.add_argument(
        '--format',
        choices=['syslog', 'json', 'csv', 'cef'],
        help='Log format hint for parsing'
    )
    
    parser.add_argument(
        '--generate-samples',
        action='store_true',
        help='Generate sample log files'
    )
    
    parser.add_argument(
        '--config',
        default='config/config.yaml',
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    if args.demo:
        return run_demo(args.config)
    elif args.parse:
        return parse_log_file(args.parse, args.format)
    elif args.generate_samples:
        return generate_samples()
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
