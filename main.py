import click
import json
from src.parsers import parse_nmap, parse_nikto, parse_dirb, parse_soc_incident
from src.report_generator import CyberReport


@click.group()
def cli():
    pass


@cli.command()
@click.option('--target', prompt='Target name/IP', help='Target that was assessed')
@click.option('--analyst', prompt='Analyst name', help='Name of the analyst')
@click.option('--nmap', default='', help='Path to nmap output file')
@click.option('--nikto', default='', help='Path to nikto output file')
@click.option('--dirb', default='', help='Path to dirb output file')
@click.option('--output', default='reports/pentest_report.pdf', help='Output PDF path')
def pentest(target, analyst, nmap, nikto, dirb, output):
    click.echo('Generating Penetration Test Report...')

    nmap_data = {'tool': 'nmap', 'findings': [], 'total': 0}
    nikto_data = {'tool': 'nikto', 'findings': [], 'total': 0}
    dirb_data = {'tool': 'dirb', 'findings': [], 'total': 0}

    if nmap:
        with open(nmap) as f:
            nmap_data = parse_nmap(f.read())

    if nikto:
        with open(nikto) as f:
            nikto_data = parse_nikto(f.read())

    if dirb:
        with open(dirb) as f:
            dirb_data = parse_dirb(f.read())

    total = nmap_data['total'] + nikto_data['total'] + dirb_data['total']
    summary = {
        'total_findings': total,
        'critical': 0,
        'high': sum(1 for f in nikto_data['findings'] if f.get('severity') == 'High'),
        'medium': sum(1 for f in nikto_data['findings'] if f.get('severity') == 'Medium'),
        'low': nmap_data['total'] + dirb_data['total']
    }

    pdf = CyberReport()
    pdf.cover_page(
        title='Penetration Test Report',
        target=target,
        analyst=analyst,
        report_type='Penetration Testing'
    )
    pdf.add_page()
    pdf.executive_summary(summary)
    pdf.add_nmap_findings(nmap_data)
    pdf.add_nikto_findings(nikto_data)
    pdf.add_dirb_findings(dirb_data)
    pdf.add_recommendations('pentest')
    pdf.output(output)

    click.echo(f'Report saved to {output}')


@cli.command()
@click.option('--incident-file', prompt='Path to incident JSON file', help='JSON file with incident data')
@click.option('--analyst', prompt='Analyst name', help='Name of the analyst')
@click.option('--output', default='reports/soc_report.pdf', help='Output PDF path')
def soc(incident_file, analyst, output):
    click.echo('Generating SOC Incident Report...')

    with open(incident_file, encoding='utf-8-sig') as f:
        incident_data = json.load(f)

    parsed = parse_soc_incident(incident_data)
    severity = incident_data.get('severity', 'Medium')

    summary = {
        'total_findings': parsed['total'],
        'critical': 1 if severity == 'Critical' else 0,
        'high': 1 if severity == 'High' else 0,
        'medium': 1 if severity == 'Medium' else 0,
        'low': 1 if severity == 'Low' else 0
    }

    pdf = CyberReport()
    pdf.cover_page(
        title='SOC Incident Report',
        target=incident_data.get('title', 'Security Incident'),
        analyst=analyst,
        report_type='SOC Incident Response'
    )
    pdf.add_page()
    pdf.executive_summary(summary)
    pdf.add_soc_incident(parsed)
    pdf.add_recommendations('soc')
    pdf.output(output)

    click.echo(f'Report saved to {output}')


if __name__ == '__main__':
    cli()
