--
-- PostgreSQL database dump
--

-- Dumped from database version 11.8 (Ubuntu 11.8-1.pgdg16.04+1)
-- Dumped by pg_dump version 11.8 (Ubuntu 11.8-1.pgdg16.04+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: sumav
--

--CREATE SCHEMA public;


-- ALTER SCHEMA public OWNER TO sumav;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: detection; Type: TABLE; Schema: public; Owner: sumav
--

CREATE TABLE public.detection (
    id bigint NOT NULL,
    "submission.date" timestamp with time zone,
    md5 bytea,
    sha1 bytea,
    sha256 bytea,
    type character varying(60),
    ground_truth character varying(60),
    sumav_label character varying(100),
    "scans.AegisLab.result" character varying(100),
    "scans.AhnLab-V3.result" character varying(100),
    "scans.Alibaba.result" character varying(100),
    "scans.Avast.result" character varying(100),
    "scans.Avira.result" character varying(100),
    "scans.Baidu.result" character varying(100),
    "scans.BitDefender.result" character varying(100),
    "scans.Bkav.result" character varying(100),
    "scans.CAT-QuickHeal.result" character varying(100),
    "scans.CMC.result" character varying(100),
    "scans.ClamAV.result" character varying(100),
    "scans.Comodo.result" character varying(100),
    "scans.Cyren.result" character varying(100),
    "scans.DrWeb.result" character varying(100),
    "scans.ESET-NOD32.result" character varying(100),
    "scans.F-Secure.result" character varying(100),
    "scans.FireEye.result" character varying(100),
    "scans.Fortinet.result" character varying(100),
    "scans.Ikarus.result" character varying(100),
    "scans.Jiangmin.result" character varying(100),
    "scans.Kaspersky.result" character varying(100),
    "scans.Malwarebytes.result" character varying(100),
    "scans.McAfee.result" character varying(100),
    "scans.Microsoft.result" character varying(100),
    "scans.NANO-Antivirus.result" character varying(100),
    "scans.Panda.result" character varying(100),
    "scans.Qihoo-360.result" character varying(100),
    "scans.SUPERAntiSpyware.result" character varying(100),
    "scans.Sophos.result" character varying(100),
    "scans.Symantec.result" character varying(100),
    "scans.TACHYON.result" character varying(100),
    "scans.Tencent.result" character varying(100),
    "scans.TotalDefense.result" character varying(100),
    "scans.TrendMicro.result" character varying(100),
    "scans.VBA32.result" character varying(100),
    "scans.VIPRE.result" character varying(100),
    "scans.ViRobot.result" character varying(100),
    "scans.Webroot.result" character varying(100),
    "scans.Yandex.result" character varying(100),
    "scans.Zillya.result" character varying(100),
    "scans.ZoneAlarm.result" character varying(100),
    "scans.Zoner.result" character varying(100),
    tokens character varying(30)[],
    unique_tokens character varying(30)[]
);


ALTER TABLE public.detection OWNER TO sumav;

--
-- Name: detection_id_seq; Type: SEQUENCE; Schema: public; Owner: sumav
--

CREATE SEQUENCE public.detection_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.detection_id_seq OWNER TO sumav;

--
-- Name: detection_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sumav
--

ALTER SEQUENCE public.detection_id_seq OWNED BY public.detection.id;

--
-- Name: file_feed_log; Type: TABLE; Schema: public; Owner: sumav
--

CREATE TABLE public.file_feed_log (
    package timestamp with time zone NOT NULL,
    "timestamp" timestamp with time zone NOT NULL
);


ALTER TABLE public.file_feed_log OWNER TO sumav;

--
-- Name: token_edge_id_seq; Type: SEQUENCE; Schema: public; Owner: sumav
--

CREATE SEQUENCE public.token_edge_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.token_edge_id_seq OWNER TO sumav;

--
-- Name: token_edge; Type: TABLE; Schema: public; Owner: sumav
--

CREATE TABLE public.token_edge (
    id integer DEFAULT nextval('public.token_edge_id_seq'::regclass) NOT NULL,
    token character varying(100) NOT NULL,
    token2 character varying(100) NOT NULL,
    "p(token2|token)" real,
    "p(token|token2)" real,
    intersection_row_count integer NOT NULL
);


ALTER TABLE public.token_edge OWNER TO sumav;

--
-- Name: token_node; Type: TABLE; Schema: public; Owner: sumav
--

CREATE TABLE public.token_node (
    id integer NOT NULL,
    token character varying(100) NOT NULL,
    alias character varying(100),
    parents character varying(100) [],
    token_count integer NOT NULL,
    row_count integer NOT NULL,
    token_ratio real,
    num_subsets integer
);


ALTER TABLE public.token_node OWNER TO sumav;

--
-- Name: token_node_id_seq; Type: SEQUENCE; Schema: public; Owner: sumav
--

CREATE SEQUENCE public.token_node_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.token_node_id_seq OWNER TO sumav;

--
-- Name: token_node_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sumav
--

ALTER SEQUENCE public.token_node_id_seq OWNED BY public.token_node.id;


--
-- Name: detection id; Type: DEFAULT; Schema: public; Owner: sumav
--

ALTER TABLE ONLY public.detection ALTER COLUMN id SET DEFAULT nextval('public.detection_id_seq'::regclass);


--
-- Name: token_node id; Type: DEFAULT; Schema: public; Owner: sumav
--

ALTER TABLE ONLY public.token_node ALTER COLUMN id SET DEFAULT nextval('public.token_node_id_seq'::regclass);


--
-- Name: detection detection_pkey1; Type: CONSTRAINT; Schema: public; Owner: sumav
--

ALTER TABLE ONLY public.detection
    ADD CONSTRAINT detection_pkey1 PRIMARY KEY (id);


--
-- Name: file_feed_log file_feed_log_pkey; Type: CONSTRAINT; Schema: public; Owner: sumav
--

ALTER TABLE ONLY public.file_feed_log
    ADD CONSTRAINT file_feed_log_pkey PRIMARY KEY (package);


--
-- Name: token_edge token_edge_pkey; Type: CONSTRAINT; Schema: public; Owner: sumav
--

ALTER TABLE ONLY public.token_edge
    ADD CONSTRAINT token_edge_pkey PRIMARY KEY (id);


--
-- Name: token_edge token_edge_token_token2_ukey; Type: CONSTRAINT; Schema: public; Owner: sumav
--

ALTER TABLE ONLY public.token_edge
    ADD CONSTRAINT token_edge_token_token2_ukey UNIQUE (token, token2);


--
-- Name: token_node token_node_pkey; Type: CONSTRAINT; Schema: public; Owner: sumav
--

ALTER TABLE ONLY public.token_node
    ADD CONSTRAINT token_node_pkey PRIMARY KEY (id);


--
-- Name: token_node token_node_token_ukey; Type: CONSTRAINT; Schema: public; Owner: sumav
--

ALTER TABLE ONLY public.token_node
    ADD CONSTRAINT token_node_token_ukey UNIQUE (token);


--
-- Name: detection_md5_idx; Type: INDEX; Schema: public; Owner: sumav
--

CREATE INDEX detection_md5_idx ON public.detection USING btree (md5);


--
-- Name: detection_sha256_idx; Type: INDEX; Schema: public; Owner: sumav
--

CREATE INDEX detection_sha256_idx ON public.detection USING btree (sha256);


--
-- Name: detection_unique_tokens_idx; Type: INDEX; Schema: public; Owner: sumav
--

CREATE INDEX detection_unique_tokens_idx ON public.detection USING gin (unique_tokens);


--
-- PostgreSQL database dump complete
--

