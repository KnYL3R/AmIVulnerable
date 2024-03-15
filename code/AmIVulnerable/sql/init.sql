/*
CREATE TABLE IF NOT EXISTS cve.cve(
    cve_number VARCHAR(20) PRIMARY KEY NOT NULL,
    designation VARCHAR(500) NOT NULL,
    version_affected TEXT NOT NULL,
    full_text MEDIUMTEXT NOT NULL
);

INSERT INTO cve (cve_number, designation, version_affected)
VALUES  ('CVE-2016-582384','dummy 1','< 1.0.3'),
        ('CVE-2019-482384','dummy 5a','< 3.0.3'),
        ('CVE-2019-182384','dummy 21a','< 2.4.3'),
        ('CVE-2019-284384','dummy 5a','< 1.5.3'),
        ('CVE-2019-588384','dummy 31a','< 2.0.3'),
        ('CVE-2019-587384','dummy r23v','< 6.0.3'),
        ('CVE-2019-582984','dummy v123','< 1.4.3'),
        ('CVE-2019-582784','dummy 5a','< 1.4.6'),
        ('CVE-2019-582344','dummy 5v123','< 1.1.12'),
        ('CVE-2019-582383','dummy v123a','< 2.1.3'),
        ('CVE-2019-582387','dummy 5v14 143a','< 7.8.3'),
        ('CVE-2018-312397','dummy 2','> 1.5.6');

CREATE INDEX idx_designation ON cve (designation);
*/
