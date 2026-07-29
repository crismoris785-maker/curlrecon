import asyncio
import json
import time

import click
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from curlrecon.core import ReconEngine
from curlrecon.models import ScanReport
from curlrecon.report import generate_html_report
from curlrecon.art import get_random_art

console = Console()


@click.command()
@click.argument("target", required=False)
@click.option(
    "-X", "--request", default="GET", help="HTTP Method (GET, POST, HEAD, etc.)"
)
@click.option("-H", "--header", multiple=True, help="Custom HTTP headers")
@click.option("-A", "--user-agent", default="CurlRecon/1.1", help="User-Agent string")
@click.option("-x", "--proxy", help="HTTP/SOCKS5 proxy")
@click.option("-k", "--insecure", is_flag=True, help="Disable TLS/SSL verification")
@click.option("-d", "--data", help="String payload for POST/PUT")
@click.option(
    "-L", "--location/--no-location", default=True, help="Toggle following redirects"
)
@click.option("--timeout", default=10.0, type=float, help="Network timeout in seconds")
@click.option(
    "-l", "--file", type=click.Path(exists=True), help="Path to target URLs file"
)
@click.option("-t", "--threads", default=10, type=int, help="Concurrent workers")
@click.option("--json-out", is_flag=True, help="Output raw JSON to stdout")
@click.option("--html-out", type=click.Path(), help="Path to export HTML report")
@click.option(
    "-o", "--output", type=click.Path(), help="Path to write JSON output directly"
)
def cli(
    target,
    request,
    header,
    user_agent,
    proxy,
    insecure,
    data,
    location,
    timeout,
    file,
    threads,
    json_out,
    html_out,
    output,
):
    """CurlRecon - Advanced CLI Reconnaissance Tool"""
    from rich.prompt import Prompt, Confirm

    if not target and not file:
        console.print(f"[bold magenta]{get_random_art()}[/bold magenta]")
        while True:
            console.print("\n[bold cyan]=== CurlRecon Interactive Menu ===[/bold cyan]")
            console.print("1. Standard Scan (Single Target)")
            console.print("2. Advanced Scan (Custom Headers)")
            console.print("3. Multi-Target Scan (From File)")
            console.print("4. Help / About")
            console.print("5. Exit")
            
            choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3", "4", "5"], default="1")
            
            if choice == "5":
                return
            elif choice == "4":
                console.print("\n[bold]CurlRecon Help[/bold]")
                console.print("This tool performs tech stack fingerprinting and security header analysis.")
                console.print("You can bypass this menu by passing flags (e.g., `python -m curlrecon.cli https://example.com`).\n")
                continue
            
            console.print("[dim](Type 'cancel' at any time to return to menu)[/dim]")
            
            if choice in ["1", "2"]:
                t = Prompt.ask("\nEnter Target URL")
                if t.lower() == 'cancel' or not t:
                    continue
                target = t
                
                req = Prompt.ask("HTTP Method", choices=["GET", "POST", "HEAD", "OPTIONS", "PUT"], default="GET")
                if req.lower() == 'cancel':
                    target = None
                    continue
                request = req
                
                if choice == "2":
                    h = Prompt.ask("Custom Header (e.g., Authorization: Bearer token)")
                    if h and h.lower() != 'cancel':
                        header = (h,)
            
            elif choice == "3":
                f = Prompt.ask("\nEnter path to targets file (e.g., targets.txt)")
                if f.lower() == 'cancel' or not f:
                    continue
                import os
                if not os.path.exists(f):
                    console.print(f"[red]Error: File '{f}' not found.[/red]")
                    continue
                file = f
            
            if Confirm.ask("\nGenerate HTML Report?", default=True):
                html_out = Prompt.ask("Report filename", default="report.html")
            
            break

    targets = []
    if target:
        targets.append(target)

    if file:
        with open(file, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    headers_dict = {}
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers_dict[k.strip()] = v.strip()

    engine = ReconEngine(
        method=request,
        headers=headers_dict,
        user_agent=user_agent,
        proxy=proxy,
        insecure=insecure,
        data=data,
        location=location,
        timeout=timeout,
        threads=threads,
    )

    if not json_out:
        console.print(
            f"[bold blue]Starting CurlRecon Scan against {len(targets)} target(s)...[/bold blue]"
        )

    start_time = time.perf_counter()
    results = asyncio.run(engine.run(targets))
    duration = time.perf_counter() - start_time

    successful = sum(1 for r in results if r.success)
    failed = len(results) - successful

    report = ScanReport(
        targets=results,
        total_scanned=len(results),
        successful=successful,
        failed=failed,
        scan_duration=duration,
    )

    # Output generation
    if json_out:
        print(json.dumps(report.model_dump(), indent=2))
    elif not json_out:
        for res in results:
            if res.success:
                status_color = "green" if res.response.status_code < 400 else "yellow"
                console.print(
                    f"\n[bold]{res.url}[/bold] -> [{status_color}]{res.response.status_code}[/{status_color}] ({res.response.elapsed_seconds:.2f}s)"
                )

                if res.fingerprints:
                    fp_parts = []
                    for fp in res.fingerprints:
                        base = f"{fp.category}:{fp.name}"
                        if fp.version:
                            base += f" v{fp.version}"
                        fp_parts.append(base)
                    fp_str = ", ".join(fp_parts)
                    console.print(f"  [cyan]Stack:[/cyan] {fp_str}")

                if res.security:
                    score = res.security.score
                    score_color = (
                        "green" if score >= 80 else "yellow" if score >= 40 else "red"
                    )
                    console.print(
                        f"  [cyan]Security Score:[/cyan] [{score_color}]{score}/100[/{score_color}]"
                    )
            else:
                console.print(
                    f"\n[bold]{res.url}[/bold] -> [red]FAILED[/red]: {res.error}"
                )

        console.print(
            f"\n[bold green]Scan Complete:[/bold green] {successful} success, {failed} failed in {duration:.2f}s"
        )

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(), f, indent=2)
        if not json_out:
            console.print(f"[green]Saved JSON output to {output}[/green]")

    if html_out:
        generate_html_report(report, html_out)
        if not json_out:
            console.print(f"[green]Saved HTML report to {html_out}[/green]")


if __name__ == "__main__":
    cli()
