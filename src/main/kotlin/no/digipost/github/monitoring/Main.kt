package no.digipost.github.monitoring

import com.apollographql.apollo3.ApolloClient
import com.apollographql.apollo3.api.http.HttpHeader
import com.github.graphql.client.type.SecurityAdvisorySeverity
import io.micrometer.core.instrument.MultiGauge
import io.micrometer.core.instrument.Tags
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.isActive
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import no.digipost.monitoring.micrometer.ApplicationInfoMetrics
import no.digipost.monitoring.prometheus.SimplePrometheusServer
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.util.Optional
import java.util.concurrent.atomic.AtomicLong
import kotlin.jvm.optionals.getOrNull
import kotlin.system.measureTimeMillis

val LANGUAGES = setOf("JavaScript", "Java", "TypeScript", "C#", "Kotlin", "Go", "Shell", "Dockerfile")
val POSSIBLE_CONTAINER_SCAN = setOf("JavaScript", "Java", "TypeScript", "Kotlin", "Shell", "Dockerfile")
val GITHUB_SECRET_PATH = Path.of("/secrets/githubtoken.txt")
val SLACK_WEBHOOK_URL_PATH = Path.of("/secrets/slack-webhook-url.txt")
const val GITHUB_OWNER = "digipost"
const val TIMOUT_PUBLISH_VULNS = 1000L * 60 * 2
const val DELAY_BETWEEN_PUBLISH_VULNS = 1000L * 60 * 5

var existingVulnerabilities: Map<String, Vulnerability>? = null

var VULNERABILITY_ORDERING = listOf(SecurityAdvisorySeverity.CRITICAL, SecurityAdvisorySeverity.HIGH, SecurityAdvisorySeverity.MODERATE, SecurityAdvisorySeverity.LOW, SecurityAdvisorySeverity.UNKNOWN__)

suspend fun main(): Unit = coroutineScope {
    val isLocal = getEnvOrProp("env").getOrNull() == "local"

    val githubToken = if (isLocal) getEnvOrProp("token").get() else withContext(Dispatchers.IO) {
        Files.readString(GITHUB_SECRET_PATH).trim()
    }

    val slackWebhookUrl: String? = if (isLocal) getEnvOrProp("SLACK_WEBHOOK_URL").getOrNull() else withContext(Dispatchers.IO) {
        if (Files.exists(SLACK_WEBHOOK_URL_PATH)) {
            Files.readString(SLACK_WEBHOOK_URL_PATH).trim()
        } else {
            null
        }
    }

    val severityLimitForNotifications = SecurityAdvisorySeverity.safeValueOf(getEnvOrProp("severity_limit").orElse("UNKNOWN"))
    val logger = LoggerFactory.getLogger("no.digipost.github.monitoring.Main")
    val prometheusMeterRegistry = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)

    ApplicationInfoMetrics().bindTo(prometheusMeterRegistry)

    val multiGaugeRepoVulnCount = MultiGauge.builder("repository_vulnerability_count")
        .tags("owner", GITHUB_OWNER)
        .register(prometheusMeterRegistry)

    val multiGaugeContainerScan = MultiGauge.builder("repository_container_scan")
        .tags("owner", GITHUB_OWNER)
        .register(prometheusMeterRegistry)

    val multiGaugeInfoScore = MultiGauge.builder("vulnerability_info_score")
        .tags("owner", GITHUB_OWNER)
        .register(prometheusMeterRegistry)

    val apolloClientFactory = cachedApolloClientFactory(githubToken)
    val githubApiClient = GithubApiClient(githubToken)
    val slackClient = slackWebhookUrl?.let{ SlackClient(it) }

    launch {
        while (isActive) {
            try {
                withTimeout(TIMOUT_PUBLISH_VULNS) {
                    val timeMillis = measureTimeMillis {
                        publish(apolloClientFactory.invoke(), githubApiClient, slackClient, severityLimitForNotifications, multiGaugeRepoVulnCount, multiGaugeContainerScan, multiGaugeInfoScore)
                    }
                    logger.info("Henting av repos med sårbarheter tok ${timeMillis}ms")
                }
            } catch (e: TimeoutCancellationException) {
                logger.warn("Henting av repos med sårbarheter brukte for lang tid (timeout) $e")
            }
            delay(DELAY_BETWEEN_PUBLISH_VULNS)
        }
        logger.warn("Hovedjobben er ikke aktiv lenger og avslutter")
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
            age.set(System.currentTimeMillis())
            client
        }
    }
}

suspend fun publish(apolloClient: ApolloClient, githubApiClient: GithubApiClient, slackClient: SlackClient?, severityLimit: SecurityAdvisorySeverity, registerRepos: MultiGauge, registerContainerScanStats: MultiGauge, registerVulnerabilites: MultiGauge): Unit = coroutineScope {

    val channel = Channel<Repos>()
    launch {
        fetchAllReposWithVulnerabilities(apolloClient, githubApiClient)
            .let { repos ->
                if (existingVulnerabilities != null) {
                    repos.getUniqueCVEs()
                        .filter { (cve, vulnerability) -> !existingVulnerabilities!!.containsKey(cve) && VULNERABILITY_ORDERING.indexOf(vulnerability.severity) <= VULNERABILITY_ORDERING.indexOf(severityLimit) }
                        .forEach { (_, vulnerability) ->
                            println("Ny sårbarhet: $vulnerability")
                            slackClient?.sendToSlack(vulnerability)
                        }
                }

                existingVulnerabilities = repos.getUniqueCVEs()
                channel.send(repos)
            }
    }

    launch {
        channel.receive().also { repos ->
            val all = repos.all
            val onlyVulnerable = all.filter { it.vulnerabilities.isNotEmpty() }
            val onlyContainerScan = all.filter { it.containerScanStats != null }

            logger.info("Antall repos: {}", all.size)
            logger.info("Antall med sårbarheter: {}", onlyVulnerable.size)
            logger.info("Antall sårbarheter å rette: {}", onlyVulnerable.flatMap { it.vulnerabilities }.count())
            logger.info("Antall som feiler containerscan: {}", onlyContainerScan.map { it.containerScanStats?.passes }.count())
            logger.info("Gjennomsnittlig suksess for containerscan: {}%", onlyContainerScan.mapNotNull { it.containerScanStats?.passPercentage }.average())

            all.map { repo ->
                MultiGauge.Row.of(Tags.of("name", repo.name, "language", repo.language), repo.vulnerabilities.size)
            }.let { registerRepos.register(it, true) }

            onlyVulnerable.map { repo ->
                repo.vulnerabilities.map { vuln ->
                    MultiGauge.Row.of(
                        Tags.of(
                            "name", repo.name,
                            "language", repo.language,
                            "created", vuln.createdAt,
                            "CVE", vuln.CVE,
                            "packagename", vuln.packageName,
                            "severity", vuln.severity.name,
                        ), vuln.score
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

private fun getEnvOrProp(propName: String): Optional<String> {
    var result = System.getenv(propName)
    if (result != null) return Optional.of(result)
    result = System.getProperty(propName)

    return Optional.ofNullable(result)
}
