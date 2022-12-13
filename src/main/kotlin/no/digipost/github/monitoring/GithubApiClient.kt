package no.digipost.github.monitoring

import com.google.gson.Gson
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpResponse.BodyHandlers
import java.time.LocalDate
import java.time.format.DateTimeFormatter

const val GITHUB_WORKFLOW_RUNS_URI = "https://api.github.com/repos/%s/%s/actions/runs?created=%s&event=schedule&per_page=%s"
const val GITHUB_WORKFLOWS_URI = "https://api.github.com/repos/%s/%s/actions/workflows"

private const val SCAN_CONTAINERS_YML = "scan-containers.yml"

class GithubApiClient(private val githubToken: String) {

    val client: HttpClient = HttpClient.newBuilder().build()
    private val formatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
    private var cache: HashMap<String, Boolean> = hashMapOf()

    fun fetchWorkflowRuns(repo: Repository, days: Int): List<WorkflowRun> {
        return if (cache.getOrPut(repo.name) { hasContainerScanWorkflow(repo) }) {
            fetchRuns(repo, days)
        } else {
            emptyList()
        }
    }

    private fun hasContainerScanWorkflow(repo: Repository): Boolean {
        return fetchWorkflows(repo).workflows.any { it.path.contains(SCAN_CONTAINERS_YML) }
    }

    private fun fetchWorkflows(repo: Repository): Workflows {
        val workflowsUri = GITHUB_WORKFLOWS_URI.format(repo.owner, repo.name)
        val workflowsRequest: HttpRequest = githubApiRequest(workflowsUri)
        val workflowsResponse: HttpResponse<String> = client.send(workflowsRequest, BodyHandlers.ofString())
        return Gson().fromJson(workflowsResponse.body(), Workflows::class.java)
    }

    private fun fetchRuns(repo: Repository, days: Int): List<WorkflowRun> {
        val uri: String = GITHUB_WORKFLOW_RUNS_URI.format(repo.owner, repo.name, datetimeRange(days), days)
        val request: HttpRequest = githubApiRequest(uri)
        val response: HttpResponse<String> = client.send(request, BodyHandlers.ofString())
        val workflowRuns: WorkflowRuns = Gson().fromJson(response.body(), WorkflowRuns::class.java)
        return workflowRuns.workflowRuns.filter { it.isScheduledContainerScan() }
    }

    private fun githubApiRequest(uri: String): HttpRequest {
        return HttpRequest
            .newBuilder()
            .uri(URI.create(uri))
            .header("Authorization", "Bearer $githubToken")
            .header("Accept", "application/vnd.github+json")
            .build()
    }

    private fun datetimeRange(days: Int): String {
        val current = LocalDate.now()
        val past = current.minusDays((days - 1).toLong())
        return "%s..%s".format(past.format(formatter), current.format(formatter))
    }

}
