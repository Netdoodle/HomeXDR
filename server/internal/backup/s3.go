package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// S3 is a minimal client for S3-compatible object storage (AWS S3, Backblaze B2, Wasabi,
// Cloudflare R2, MinIO, ...): Signature Version 4, single PUT for small objects,
// multipart upload for archives, GET, HEAD, DELETE and LIST. Payloads are signed with
// their SHA-256, which every provider accepts.
type S3 struct {
	Endpoint     string // https://s3.us-east-1.amazonaws.com
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	PathStyle    bool   // https://host/bucket/key instead of https://bucket.host/key
	StorageClass string // optional x-amz-storage-class for uploads
	HTTP         *http.Client
	now          func() time.Time
}

func (c *S3) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

// objectURL builds the URL of key (empty key: the bucket).
func (c *S3) objectURL(key string, q url.Values) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(c.Endpoint, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("endpoint must be an http(s) URL such as https://s3.us-east-1.amazonaws.com")
	}
	esc := escapePath(key)
	if c.PathStyle {
		u.Path = "/" + c.Bucket
		if key != "" {
			u.Path += "/" + key
		}
		u.RawPath = "/" + c.Bucket
		if key != "" {
			u.RawPath += "/" + esc
		}
	} else {
		u.Host = c.Bucket + "." + u.Host
		u.Path, u.RawPath = "/"+key, "/"+esc
	}
	u.RawQuery = canonicalQuery(q)
	return u, nil
}

// escapePath URI-encodes each path segment the way SigV4 expects.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = uriEncode(s, false)
	}
	return strings.Join(parts, "/")
}

func uriEncode(s string, slash bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !slash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

// do signs and sends one request. body may be nil.
func (c *S3) do(ctx context.Context, method, key string, q url.Values, body []byte, hdr map[string]string) (*http.Response, error) {
	u, err := c.objectURL(key, q)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(body))
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	t := now().UTC()
	amzDate, day := t.Format("20060102T150405Z"), t.Format("20060102")
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payload)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	// Canonical request over host and the x-amz-* / content-type headers.
	names := []string{"host"}
	vals := map[string]string{"host": u.Host}
	for k := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-type" || lk == "content-md5" || lk == "date" {
			names = append(names, lk)
			vals[lk] = strings.TrimSpace(req.Header.Get(k))
		}
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + vals[n] + "\n")
	}
	signed := strings.Join(names, ";")
	canon := strings.Join([]string{method, u.EscapedPath(), u.RawQuery, ch.String(), signed, payload}, "\n")
	scope := day + "/" + c.Region + "/s3/aws4_request"
	cr := sha256.Sum256([]byte(canon))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(cr[:])
	k := hmacSHA256([]byte("AWS4"+c.SecretKey), day)
	k = hmacSHA256(k, c.Region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", c.AccessKey, scope, signed, sig))
	return c.client().Do(req)
}

// S3Error is an error response from the storage service.
type S3Error struct {
	Status  int
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func (e *S3Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("storage returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("storage returned %s: %s", e.Code, e.Message)
}

func check(resp *http.Response, err error) (*http.Response, error) {
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
	}
	defer resp.Body.Close()
	e := &S3Error{Status: resp.StatusCode}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = xml.Unmarshal(b, e)
	return nil, e
}

func (c *S3) uploadHeaders(contentType string) map[string]string {
	h := map[string]string{"Content-Type": contentType}
	if c.StorageClass != "" {
		h["x-amz-storage-class"] = c.StorageClass
	}
	return h
}

// Put uploads a small object in one request.
func (c *S3) Put(ctx context.Context, key, contentType string, body []byte) error {
	resp, err := check(c.do(ctx, http.MethodPut, key, nil, body, c.uploadHeaders(contentType)))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Delete removes an object.
func (c *S3) Delete(ctx context.Context, key string) error {
	resp, err := check(c.do(ctx, http.MethodDelete, key, nil, nil, nil))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Get opens an object for reading; the caller closes it.
func (c *S3) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := check(c.do(ctx, http.MethodGet, key, nil, nil, nil))
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// List returns the keys under prefix (up to max).
func (c *S3) List(ctx context.Context, prefix string, max int) ([]string, error) {
	var keys []string
	token := ""
	for len(keys) < max {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"1000"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := check(c.do(ctx, http.MethodGet, "", q, nil, nil))
		if err != nil {
			return nil, err
		}
		var out struct {
			Contents []struct {
				Key string `xml:"Key"`
			} `xml:"Contents"`
			NextToken   string `xml:"NextContinuationToken"`
			IsTruncated bool   `xml:"IsTruncated"`
		}
		err = xml.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		for _, o := range out.Contents {
			keys = append(keys, o.Key)
		}
		if !out.IsTruncated || out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return keys, nil
}

// partSize: S3 allows 10,000 parts, so 16 MiB parts cover objects up to 156 GiB.
const partSize = 16 << 20

// Upload is a multipart upload written like a file. Close completes it; Abort (or a
// failed Write/Close) discards the parts.
type Upload struct {
	c       *S3
	ctx     context.Context
	key, id string
	buf     []byte
	parts   []completedPart
	err     error
	Size    int64
}

type completedPart struct {
	XMLName xml.Name `xml:"Part"`
	Number  int      `xml:"PartNumber"`
	ETag    string   `xml:"ETag"`
}

// NewUpload starts a multipart upload.
func (c *S3) NewUpload(ctx context.Context, key, contentType string) (*Upload, error) {
	resp, err := check(c.do(ctx, http.MethodPost, key, url.Values{"uploads": {""}}, nil, c.uploadHeaders(contentType)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&out); err != nil || out.UploadID == "" {
		return nil, fmt.Errorf("start multipart upload: no upload ID (%v)", err)
	}
	return &Upload{c: c, ctx: ctx, key: key, id: out.UploadID, buf: make([]byte, 0, partSize)}, nil
}

func (u *Upload) Write(p []byte) (int, error) {
	if u.err != nil {
		return 0, u.err
	}
	n := len(p)
	for len(p) > 0 {
		room := partSize - len(u.buf)
		take := min(room, len(p))
		u.buf = append(u.buf, p[:take]...)
		p = p[take:]
		if len(u.buf) == partSize {
			if err := u.flush(); err != nil {
				return 0, err
			}
		}
	}
	u.Size += int64(n)
	return n, nil
}

func (u *Upload) flush() error {
	num := len(u.parts) + 1
	q := url.Values{"partNumber": {strconv.Itoa(num)}, "uploadId": {u.id}}
	var resp *http.Response
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = check(u.c.do(u.ctx, http.MethodPut, u.key, q, u.buf, nil))
		if err == nil {
			break
		}
		select {
		case <-u.ctx.Done():
			u.err = u.ctx.Err()
			return u.err
		case <-time.After(time.Duration(attempt+1) * 3 * time.Second):
		}
	}
	if err != nil {
		u.err = fmt.Errorf("upload part %d: %w", num, err)
		return u.err
	}
	resp.Body.Close()
	u.parts = append(u.parts, completedPart{Number: num, ETag: resp.Header.Get("ETag")})
	u.buf = u.buf[:0]
	return nil
}

// Close uploads the last part and completes the upload.
func (u *Upload) Close() error {
	if u.err != nil {
		u.Abort()
		return u.err
	}
	if len(u.buf) > 0 || len(u.parts) == 0 {
		if err := u.flush(); err != nil {
			u.Abort()
			return err
		}
	}
	body, _ := xml.Marshal(struct {
		XMLName xml.Name        `xml:"CompleteMultipartUpload"`
		Parts   []completedPart `xml:"Part"`
	}{Parts: u.parts})
	resp, err := check(u.c.do(u.ctx, http.MethodPost, u.key, url.Values{"uploadId": {u.id}}, body, map[string]string{"Content-Type": "application/xml"}))
	if err != nil {
		u.Abort()
		return fmt.Errorf("complete upload: %w", err)
	}
	defer resp.Body.Close()
	// S3 can answer 200 with an error document.
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if bytes.Contains(b, []byte("<Error>")) {
		e := &S3Error{Status: resp.StatusCode}
		_ = xml.Unmarshal(b, e)
		return e
	}
	return nil
}

// Abort discards an unfinished upload.
func (u *Upload) Abort() {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(u.ctx), 30*time.Second)
	defer cancel()
	if resp, err := u.c.do(ctx, http.MethodDelete, u.key, url.Values{"uploadId": {u.id}}, nil, nil); err == nil {
		resp.Body.Close()
	}
	if u.err == nil {
		u.err = errors.New("upload aborted")
	}
}
