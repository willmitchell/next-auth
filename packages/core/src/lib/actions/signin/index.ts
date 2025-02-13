import { getAuthorizationUrl } from "./authorization-url.js"
import { sendToken } from "./send-token.js"

import type { Cookie } from "../../utils/cookie.js"
import type {
  InternalOptions,
  RequestInternal,
  ResponseInternal,
} from "../../../types.js"

export async function signIn(
  request: RequestInternal,
  cookies: Cookie[],
  options: InternalOptions
): Promise<ResponseInternal> {
  const signInUrl = `${options.url.origin}${options.basePath}/signin`

  options.logger.verbose("Starting signIn function")
  options.logger.verbose(`Provider type: ${options.provider?.type}`)
  options.logger.verbose(`Provider ID: ${options.provider?.id}`)

  if (!options.provider) {
    options.logger.verbose("No provider found, redirecting to signInUrl")
    return { redirect: signInUrl, cookies }
  }

  switch (options.provider.type) {
    case "oauth":
    case "oidc": {
      options.logger.verbose("Provider type is oauth or oidc")
      const { redirect, cookies: authCookies } = await getAuthorizationUrl(
        request.query,
        options
      )
      if (authCookies) cookies.push(...authCookies)
      options.logger.verbose("Ending signIn function")
      return { redirect, cookies }
    }
    case "email": {
      options.logger.verbose("Provider type is email")
      const response = await sendToken(request, options)
      options.logger.verbose("Ending signIn function")
      return { ...response, cookies }
    }
    default:
      options.logger.verbose("Provider type is default")
      options.logger.verbose("Ending signIn function")
      return { redirect: signInUrl, cookies }
  }
}
