package censeye

import (
	"context"
	"encoding/json"
	"time"

	"github.com/censys/censys-sdk-go/models/components"
	"github.com/censys/censys-sdk-go/models/operations"
	log "github.com/sirupsen/logrus"
)

// getCertificateObservations fetches historical observations for a certificate fingerprint
// from the Censys API. It returns all host observation ranges where this certificate was seen.
// The days parameter specifies how many days back to look.
func (c *Censeye) getCertificateObservations(ctx context.Context, certFingerprint string, days int) ([]components.HostObservationRange, error) {
	if c.client == nil {
		return nil, nil
	}

	// Check cache first
	if cached, ok := c.loadCertHistoryCache(certFingerprint, days); ok {
		log.Debugf("Found cached certificate history for %s (%d days)", certFingerprint, days)
		return cached, nil
	}

	// Use the specified time window for historical data
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	sstr := startTime.Format(time.RFC3339)
	estr := endTime.Format(time.RFC3339)

	req := operations.V3ThreathuntingGetHostObservationsWithCertificateRequest{
		CertificateID: certFingerprint,
		StartTime:     &sstr,
		EndTime:       &estr,
	}

	if log.GetLevel() >= log.DebugLevel {
		j, _ := json.MarshalIndent(req, "", "  ")
		log.Debugf("getCertificateObservations: Request: %s", j)
	}

	var ret []components.HostObservationRange
	page := 0
	tries := 0
	maxRetries := 3

	for {
		page++

		log.Debugf("Fetching certificate observation page %d for cert %s", page, certFingerprint)

		res, err := c.client.ThreatHunting.GetHostObservationsWithCertificate(ctx, req)
		if err != nil {
			tries++
			if tries < maxRetries {
				log.Warnf("getCertificateObservations: page %d: Error fetching cert %s, retrying (%d/%d): %v",
					page, certFingerprint, tries, maxRetries, err)
				page--
				continue
			}

			log.Errorf("getCertificateObservations: page %d: Error fetching cert %s, giving up after %d tries: %v",
				page, certFingerprint, tries, err)
			return nil, err
		}

		if log.GetLevel() >= log.DebugLevel {
			if tries > 0 {
				log.Debugf("getCertificateObservations: page %d: Succeeded after %d attempt(s) for cert %s",
					page, tries+1, certFingerprint)
			}
		}

		tries = 0

		envelope := res.GetResponseEnvelopeHostObservationResponse()
		if envelope == nil {
			log.Warnf("getCertificateObservations: page %d: nil envelope for cert %s", page, certFingerprint)
			break
		}

		result := envelope.GetResult()
		if result == nil {
			log.Warnf("getCertificateObservations: page %d: nil result for cert %s", page, certFingerprint)
			break
		}

		ranges := result.GetRanges()
		next := result.GetNextPageToken()

		log.Debugf("Got %d ranges for cert %s", len(ranges), certFingerprint)

		ret = append(ret, ranges...)

		if next == nil {
			break
		}

		req.PageToken = next
	}

	// Save to cache
	if err := c.saveCertHistoryCache(certFingerprint, days, ret); err != nil {
		log.Warnf("Failed to save certificate history to cache for %s: %v", certFingerprint, err)
	}

	return ret, nil
}
