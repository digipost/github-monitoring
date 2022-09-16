package no.digipost.github.monitoring

import com.apollographql.apollo3.ApolloClient
import com.apollographql.apollo3.api.http.HttpHeader
import io.micrometer.core.instrument.MultiGauge
import io.micrometer.core.instrument.Tags
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import no.digipost.monitoring.micrometer.ApplicationInfoMetrics
import no.digipost.monitoring.prometheus.SimplePrometheusServer
import org.slf4j.LoggerFactory

const val TOKEN = ""

val LANGUAGES = setOf("JavaScript", "Java", "TypeScript", "C#", "Kotlin")

fun main() {
    val logger = LoggerFactory.getLogger("no.digipost.github.monitoring.Main")
    val prometheusMeterRegistry = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)

    ApplicationInfoMetrics().bindTo(prometheusMeterRegistry)

    val register = MultiGauge.builder("repository_vulnerability_count")
        .tags("owner", "digipost")
        .register(prometheusMeterRegistry)

    val apolloClient = ApolloClient.Builder()
        .httpHeaders(listOf(HttpHeader("Authorization", "bearer $TOKEN")))
        .serverUrl("https://api.github.com/graphql")
        .build()

    val (all, onlyVulnerable) = fetchAllReposWithVulnerabilities(apolloClient)
    all.map {repo ->
        MultiGauge.Row.of(Tags.of("name", repo.name, "language", repo.language), repo.vulnerabilities.size)
    }.let { register.register(it) }



    println("Antall repos: ${all.size}")
    println("Antall med sårbarheter: ${onlyVulnerable.size}")
    println("Antall sårbarheter å rette: ${onlyVulnerable.flatMap { it.vulnerabilities }.count()}")

    SimplePrometheusServer(logger::info)
        .startMetricsServer(prometheusMeterRegistry, 9610)

}


