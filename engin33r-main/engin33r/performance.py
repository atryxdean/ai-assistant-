"""Performance benchmarking and async/parallel optimization"""

import time
import logging
import asyncio
import multiprocessing as mp
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import tracemalloc

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Benchmark execution result"""

    analyzer_name: str
    execution_time: float  # seconds
    vulnerabilities_found: int
    false_positives: int = 0
    false_negatives: int = 0
    performance_score: float = 0.0  # Higher is better
    parallelization: str = "sequential"  # sequential, threaded, async, multiprocess
    peak_memory_mb: float = 0.0


class PerformanceBenchmark:
    """Benchmark analyzer performance with parallel/async support"""

    def __init__(self, max_workers: int = None):
        self.results: List[BenchmarkResult] = []
        self.max_workers = max_workers or mp.cpu_count()

    def benchmark_analyzer(
        self,
        analyzer: Any,
        target: str,
        iterations: int = 1,
        parallel: bool = False,
        use_async: bool = False,
    ) -> BenchmarkResult:
        """
        Benchmark an analyzer's performance

        Measures:
        - Execution time
        - Vulnerability detection rate
        - Peak memory usage
        - False positive/negative rates
        """
        execution_times = []
        all_vulnerabilities = []
        peak_memory = 0.0
        parallel_type = "sequential"

        if parallel:
            result = self._benchmark_parallel(analyzer, target, iterations)
            return result
        elif use_async:
            result = asyncio.run(self._benchmark_async(analyzer, target, iterations))
            return result

        # Sequential benchmark
        for i in range(iterations):
            tracemalloc.start()
            start_time = time.perf_counter()

            try:
                vulnerabilities = analyzer.analyze(target)
                end_time = time.perf_counter()

                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                peak_memory = max(peak_memory, peak / 1024 / 1024)

                execution_times.append(end_time - start_time)
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                logger.error(f"Benchmark failed: {e}")
                tracemalloc.stop()

        avg_time = sum(execution_times) / len(execution_times) if execution_times else 0
        unique_vulns = len(
            set((v.file_path, v.line_number) for v in all_vulnerabilities)
        )

        result = BenchmarkResult(
            analyzer_name=analyzer.name,
            execution_time=avg_time,
            vulnerabilities_found=unique_vulns,
            parallelization="sequential",
            peak_memory_mb=peak_memory,
        )

        if avg_time > 0:
            result.performance_score = unique_vulns / avg_time

        self.results.append(result)
        return result

    def _benchmark_parallel(
        self, analyzer: Any, target: str, iterations: int
    ) -> BenchmarkResult:
        """
        Benchmark using thread pool parallelization
        """
        start_time = time.perf_counter()
        all_vulnerabilities = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(analyzer.analyze, target) for _ in range(iterations)
            ]
            for future in as_completed(futures):
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    logger.error(f"Parallel analysis failed: {e}")

        end_time = time.perf_counter()
        unique_vulns = len(
            set((v.file_path, v.line_number) for v in all_vulnerabilities)
        )

        result = BenchmarkResult(
            analyzer_name=analyzer.name,
            execution_time=end_time - start_time,
            vulnerabilities_found=unique_vulns,
            parallelization="threaded",
        )

        if result.execution_time > 0:
            result.performance_score = unique_vulns / result.execution_time

        self.results.append(result)
        return result

    async def _benchmark_async(
        self, analyzer: Any, target: str, iterations: int
    ) -> BenchmarkResult:
        """
        Benchmark using async parallelization
        """
        if not hasattr(analyzer, "analyze_async"):
            logger.warning(f"{analyzer.name} does not support async analysis")
            return self.benchmark_analyzer(analyzer, target, iterations, parallel=False)

        start_time = time.perf_counter()
        tasks = [analyzer.analyze_async(target) for _ in range(iterations)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.perf_counter()

        all_vulnerabilities = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Async analysis failed: {result}")
            else:
                all_vulnerabilities.extend(result)

        unique_vulns = len(
            set((v.file_path, v.line_number) for v in all_vulnerabilities)
        )

        result = BenchmarkResult(
            analyzer_name=analyzer.name,
            execution_time=end_time - start_time,
            vulnerabilities_found=unique_vulns,
            parallelization="async",
        )

        if result.execution_time > 0:
            result.performance_score = unique_vulns / result.execution_time

        self.results.append(result)
        return result

    def compare_analyzers(
        self, analyzers: List[Any], target: str, parallel: bool = False
    ) -> Dict[str, Any]:
        """
        Compare multiple analyzers on same target
        """
        comparison = {}

        for analyzer in analyzers:
            result = self.benchmark_analyzer(analyzer, target, parallel=parallel)
            comparison[analyzer.name] = {
                "time": result.execution_time,
                "vulns": result.vulnerabilities_found,
                "score": result.performance_score,
                "memory_mb": result.peak_memory_mb,
                "parallelization": result.parallelization,
            }

        return comparison

    def get_summary(self) -> str:
        """
        Get benchmark summary report
        """
        if not self.results:
            return "No benchmarks run"

        summary = "BENCHMARK RESULTS\n" + "=" * 80 + "\n\n"
        summary += f"System Info: {self.max_workers} CPU cores available\n\n"

        for result in sorted(
            self.results, key=lambda r: r.performance_score, reverse=True
        ):
            summary += f"{result.analyzer_name}:\n"
            summary += f"  Execution Time: {result.execution_time:.4f}s\n"
            summary += f"  Vulnerabilities Found: {result.vulnerabilities_found}\n"
            summary += (
                f"  Performance Score: {result.performance_score:.2f} vulns/sec\n"
            )
            summary += f"  Peak Memory: {result.peak_memory_mb:.2f} MB\n"
            summary += f"  Parallelization: {result.parallelization}\n\n"

        return summary


class AsyncPerformanceOptimizer:
    """Optimize scanning with async/parallel patterns"""

    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or mp.cpu_count()

    async def analyze_multiple_targets_async(
        self, analyzer: Any, targets: List[str]
    ) -> Dict[str, List[Any]]:
        """
        Analyze multiple targets concurrently using async
        """
        if not hasattr(analyzer, "analyze_async"):
            logger.warning(f"{analyzer.name} doesn't support async")
            return self.analyze_multiple_targets_threaded(analyzer, targets)

        tasks = {target: analyzer.analyze_async(target) for target in targets}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        output = {}
        for target, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                logger.error(f"Failed to analyze {target}: {result}")
                output[target] = []
            else:
                output[target] = result

        return output

    def analyze_multiple_targets_threaded(
        self, analyzer: Any, targets: List[str]
    ) -> Dict[str, List[Any]]:
        """
        Analyze multiple targets in parallel using thread pool
        """
        output = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(analyzer.analyze, target): target for target in targets
            }

            for future in as_completed(futures):
                target = futures[future]
                try:
                    output[target] = future.result()
                except Exception as e:
                    logger.error(f"Failed to analyze {target}: {e}")
                    output[target] = []

        return output

    def analyze_batch_parallel(
        self, analyzers: List[Any], target: str
    ) -> Dict[str, List[Any]]:
        """
        Run multiple analyzers in parallel on same target
        """
        output = {}

        with ThreadPoolExecutor(max_workers=len(analyzers)) as executor:
            futures = {executor.submit(a.analyze, target): a.name for a in analyzers}

            for future in as_completed(futures):
                analyzer_name = futures[future]
                try:
                    output[analyzer_name] = future.result()
                except Exception as e:
                    logger.error(f"Analyzer {analyzer_name} failed: {e}")
                    output[analyzer_name] = []

        return output


class MemoryProfiler:
    """Profile memory usage during scanning"""

    @staticmethod
    def measure_memory(func: Callable) -> Dict[str, Any]:
        """
        Measure peak memory usage of function
        """
        try:
            tracemalloc.start()

            start_time = time.time()
            result = func()
            end_time = time.time()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            return {
                "result": result,
                "current_memory_mb": current / 1024 / 1024,
                "peak_memory_mb": peak / 1024 / 1024,
                "execution_time": end_time - start_time,
            }
        except Exception as e:
            logger.error(f"Memory profiling failed: {e}")
            return {"result": func()}

    @staticmethod
    async def measure_memory_async(func: Callable) -> Dict[str, Any]:
        """
        Measure peak memory usage of async function
        """
        try:
            tracemalloc.start()

            start_time = time.time()
            result = await func()
            end_time = time.time()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            return {
                "result": result,
                "current_memory_mb": current / 1024 / 1024,
                "peak_memory_mb": peak / 1024 / 1024,
                "execution_time": end_time - start_time,
            }
        except Exception as e:
            logger.error(f"Async memory profiling failed: {e}")
            return {"result": await func()}
