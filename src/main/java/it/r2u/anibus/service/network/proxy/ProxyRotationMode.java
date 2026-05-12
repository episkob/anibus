package it.r2u.anibus.service.network.proxy;

/** Rotation/selection mode for active proxy choice. */
public enum ProxyRotationMode {
    /** Fastest candidate from geo strategy and active policy filters. */
    FASTEST,
    /** Actively probes candidate connectivity before selection. */
    STABLE,
    /** Prefers geo/fast path, falls back to stable probe when health is low. */
    BALANCED
}
