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
import kotlin.system.measureTimeMillis

val LANGUAGES = setOf("JavaScript", "Java", "TypeScript", "C#", "Kotlin")

suspend fun main(): Unit = coroutineScope {
    val env = System.getenv("env")
    val token = if(env == "local") System.getenv("token") else withContext(Dispatchers.IO) {
        Files.readString(Path.of("/secrets/githubtoken.txt")).trim()
    }

    val logger = LoggerFactory.getLogger("no.digipost.github.monitoring.Main")
    val prometheusMeterRegistry = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)

    ApplicationInfoMetrics().bindTo(prometheusMeterRegistry)

    val multiGauge = MultiGauge.builder("repository_vulnerability_count")
        .tags("owner", "digipost")
        .register(prometheusMeterRegistry)

    val apolloClient = ApolloClient.Builder()
        .httpHeaders(listOf(HttpHeader("Authorization", "bearer $token")))
        .serverUrl("https://api.github.com/graphql")
        .build()

    launch {
        while (isActive) {
            val timeMillis = measureTimeMillis {
                publish(apolloClient, multiGauge)
            }
            logger.info("Henting av repos med sårbarheter tok ${timeMillis}ms")
            delay(1000 * 60 * 5)
        }
    }


    SimplePrometheusServer(logger::info)
        .startMetricsServer(prometheusMeterRegistry, 9610)
}

suspend fun publish(apolloClient: ApolloClient, register: MultiGauge): Unit = coroutineScope {

    val channel = Channel<Repos>()
    launch {
        fetchAllReposWithVulnerabilities(apolloClient)
            .let { channel.send(it) }
    }

    launch {
        channel.receive().also { repos ->
            val (all, onlyVulnerable) = repos

            logger.info("Antall repos: ${all.size}")
            logger.info("Antall med sårbarheter: ${onlyVulnerable.size}")
            logger.info("Antall sårbarheter å rette: ${onlyVulnerable.flatMap { it.vulnerabilities }.count()}")
        }.all.map { repo ->
            MultiGauge.Row.of(Tags.of("name", repo.name, "language", repo.language), repo.vulnerabilities.size)
        }.let { register.register(it) }
    }

}

