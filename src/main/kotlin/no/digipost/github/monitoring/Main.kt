package no.digipost.github.monitoring

import com.apollographql.apollo3.ApolloClient
import com.apollographql.apollo3.api.http.HttpHeader
import io.micrometer.core.instrument.MultiGauge
import io.micrometer.core.instrument.Tags
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import no.digipost.monitoring.micrometer.ApplicationInfoMetrics
import no.digipost.monitoring.prometheus.SimplePrometheusServer
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicLong
import kotlin.system.measureTimeMillis

val LANGUAGES = setOf("JavaScript", "Java", "TypeScript", "C#", "Kotlin", "Go")
val POSSIBLE_CONTAINER_SCAN = setOf("JavaScript", "Java", "TypeScript", "Kotlin")

suspend fun main(): Unit = coroutineScope {
    val env = System.getenv("env")
    val token = if (env == "local") System.getenv("token") else withContext(Dispatchers.IO) {
        Files.readString(Path.of("/secrets/githubtoken.txt")).trim()
    }

    val logger = LoggerFactory.getLogger("no.digipost.github.monitoring.Main")
    val prometheusMeterRegistry = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)

    ApplicationInfoMetrics().bindTo(prometheusMeterRegistry)

    val multiGaugeRepoVulnCount = MultiGauge.builder("repository_vulnerability_count")
        .tags("owner", "digipost")
        .register(prometheusMeterRegistry)

    val multiGaugeContainerScan = MultiGauge.builder("repository_container_scan")
        .tags("owner", "digipost")
        .register(prometheusMeterRegistry)

    val multiGaugeInfoScore = MultiGauge.builder("vulnerability_info_score")
        .tags("owner", "digipost")
        .register(prometheusMeterRegistry)

    val apolloClientFactory = cachedApolloClientFactory(token)
    val githubApiClient = GithubApiClient(token)

    launch {
        while (isActive) {
            val timeMillis = measureTimeMillis {
                publish(apolloClientFactory.invoke(), githubApiClient, multiGaugeRepoVulnCount, multiGaugeContainerScan, multiGaugeInfoScore)
            }
            logger.info("Henting av repos med sårbarheter tok ${timeMillis}ms")
            delay(1000 * 60 * 5)
        }
    }

    SimplePrometheusServer(logger::info)
        .startMetricsServer(prometheusMeterRegistry, 9610)
}

fun cachedApolloClientFactory(token: String): () -> ApolloClient {

    val fakt: (String) -> ApolloClient = { t: String ->
        ApolloClient.Builder()
            .httpHeaders(listOf(HttpHeader("Authorization", "bearer $t")))
            .serverUrl("https://api.github.com/graphql")
            .build()
    }

    val age = AtomicLong(System.currentTimeMillis());
    var client = fakt(token);

    return {
        if (System.currentTimeMillis() - age.get() < 1000 * 60 * 60 * 10) {
            println("Cachet ApolloClient")
            client
        } else {
            println("Lager ny ApolloClient")
            client = fakt(token)
            age.set(System.currentTimeMillis());
            client
        }
    }
}

suspend fun publish(apolloClient: ApolloClient, githubApiClient: GithubApiClient, registerRepos: MultiGauge, registerContainerScanStats: MultiGauge, registerVulnerabilites: MultiGauge): Unit = coroutineScope {

    val channel = Channel<Repos>()
    launch {
        fetchAllReposWithVulnerabilities(apolloClient, githubApiClient)
            .let { channel.send(it) }
    }

    launch {
        channel.receive().also { repos ->
            val all = repos.all
            val onlyVulnerable = all.filter { it.vulnerabilities.isNotEmpty() }
            val onlyContainerScan = all.filter { it.containerScanStats != null }

            logger.info("Antall repos: ${all.size}")
            logger.info("Antall med sårbarheter: ${onlyVulnerable.size}")
            logger.info("Antall sårbarheter å rette: ${onlyVulnerable.flatMap { it.vulnerabilities }.count()}")
            logger.info("Antall som feiler containerscan: ${onlyContainerScan.map { it.containerScanStats?.passes }.count()}")
            logger.info("Gjennomsnittlig suksess for containerscan: ${onlyContainerScan.mapNotNull { it.containerScanStats?.passPercentage }.average()}%")

            all.map { repo ->
                MultiGauge.Row.of(Tags.of("name", repo.name, "language", repo.language), repo.vulnerabilities.size)
            }.let { registerRepos.register(it, true) }

            onlyVulnerable.map { repo ->
                repo.vulnerabilities.map { vuln ->
                    MultiGauge.Row.of(
                        Tags.of(
                            "name", repo.name,
                            "language", repo.language,
                            "CVE", vuln.CVE ?: "",
                            "packagename", vuln.packageName ?: "UNKNOWN",
                            "severity", vuln.severity ?: "UNKNOWN",
                        ), vuln.score ?: 0.0
                    )
                }
            }.flatMap { it.toList() }.let { registerVulnerabilites.register(it) }

            onlyContainerScan.map { repo ->
                MultiGauge.Row.of(
                    Tags.of(
                        "name", repo.name,
                        "language", repo.language,
                        "passes", repo.containerScanStats!!.passes.toString()
                    ), repo.containerScanStats.passPercentage
                )
            }.let { registerContainerScanStats.register(it) }

        }
    }

}

