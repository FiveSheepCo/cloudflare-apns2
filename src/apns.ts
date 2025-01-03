import { EventEmitter } from "node:events"
import { type PrivateKey, createSigner } from "fast-jwt"
import { ApnsError, type ApnsResponseError, Errors } from "./errors.js"
import { type Notification, Priority } from "./notifications/notification.js"

// APNS version
const API_VERSION = 3

// Signing algorithm for JSON web token
const SIGNING_ALGORITHM = "ES256"

// Reset our signing token every 55 minutes as reccomended by Apple
const RESET_TOKEN_INTERVAL_MS = 55 * 60 * 1000

export enum Host {
  production = "api.push.apple.com",
  development = "api.sandbox.push.apple.com",
}

export interface SigningToken {
  value: string
  timestamp: number
}

export interface ApnsOptions {
  team: string
  signingKey: string | Buffer | PrivateKey
  keyId: string
  defaultTopic?: string
  host?: Host | string
  requestTimeout?: number
  keepAlive?: boolean
}

export class ApnsClient extends EventEmitter {
  readonly team: string
  readonly keyId: string
  readonly host: Host | string
  readonly signingKey: string | Buffer | PrivateKey
  readonly defaultTopic?: string
  readonly keepAlive: boolean

  private _token: SigningToken | null

  constructor(options: ApnsOptions) {
    super()
    this.team = options.team
    this.keyId = options.keyId
    this.signingKey = options.signingKey
    this.defaultTopic = options.defaultTopic
    this.host = options.host ?? Host.production
    this.keepAlive = options.keepAlive ?? true
    this._token = null
    this._supressH2Warning()
  }

  sendMany(notifications: Notification[]) {
    const promises = notifications.map((notification) =>
      this.send(notification).catch((error: ApnsError) => ({ error })),
    )
    return Promise.all(promises)
  }

  async send(notification: Notification) {
    const headers = new Headers()
    headers.set('authorization', `bearer ${this._getSigningToken()}`)
    headers.set('apns-push-type', notification.pushType)

    const apnsTopic = notification.options.topic ?? this.defaultTopic
    if (apnsTopic) {
      headers.set('apns-topic', apnsTopic)
    }

    if (notification.priority !== Priority.immediate) {
      headers.set('apns-priority', notification.priority.toString())
    }

    const expiration = notification.options.expiration
    if (typeof expiration !== "undefined") {
      const expirationValue = typeof expiration === "number"
        ? expiration.toFixed(0)
        : (expiration.getTime() / 1000).toFixed(0)
      headers.set('apns-expiration', expirationValue)
    }

    if (notification.options.collapseId) {
      headers.set('apns-collapse-id', notification.options.collapseId)
    }

    const url = `https://${this.host}:443/${API_VERSION}/device/${encodeURIComponent(notification.deviceToken)}`
    const res = await fetch(url, {
      method: "POST",
      headers: headers,
      body: JSON.stringify(notification.buildApnsOptions()),
      keepalive: this.keepAlive,
    })

    return this._handleServerResponse(res, notification)
  }

  private async _handleServerResponse(res: Response, notification: Notification) {
    if (res.status === 200) {
      return notification
    }

    const responseError = await res.json().catch(() => ({
      reason: Errors.unknownError,
      timestamp: Date.now(),
    }))

    const error = new ApnsError({
      statusCode: res.status,
      notification: notification,
      response: responseError as ApnsResponseError,
    })

    // Reset signing token if expired
    if (error.reason === Errors.expiredProviderToken) {
      this._token = null
    }

    // Emit specific and generic errors
    this.emit(error.reason, error)
    this.emit(Errors.error, error)

    throw error
  }

  private _getSigningToken(): string {
    if (this._token && Date.now() - this._token.timestamp < RESET_TOKEN_INTERVAL_MS) {
      return this._token.value
    }

    const claims = {
      iss: this.team,
      iat: Math.floor(Date.now() / 1000),
    }

    const signer = createSigner({
      key: this.signingKey,
      algorithm: SIGNING_ALGORITHM,
      kid: this.keyId,
    })

    const token = signer(claims)

    this._token = {
      value: token,
      timestamp: Date.now(),
    }

    return token
  }

  private _supressH2Warning() {
    process.once("warning", (warning: Error & { code?: string }) => {
      if (warning.code === "UNDICI-H2") {
        return
      }
      process.emit("warning", warning)
    })
  }
}
