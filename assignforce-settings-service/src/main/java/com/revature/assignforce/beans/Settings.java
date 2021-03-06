package com.revature.assignforce.beans;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

import org.springframework.stereotype.Component;

@Component
@Entity
@Table(name = "Settings")
public class Settings {

	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "Settings_ID")
	@SequenceGenerator(name = "Settings_ID", sequenceName = "Settings_ID_seq", allocationSize = 1)
	@Column(name = "Settings_ID")
	private Integer id;

	@Column(name = "Alias")
	private String alias;

	@Column(name = "trainersPerPage")
	private Integer trainersPerPage;

	@Column(name = "batchLength")
	private Integer batchLength;

	@Column(name = "reportIncomingCandidates")
	private Integer reportIncomingCandidates;

	@Column(name = "reportOutgoingGrads")
	private Integer reportOutgoingGrads;

	@Column(name = "minBatchSize")
	private Integer minBatchSize;

	@Column(name = "maxBatchSize")
	private Integer maxBatchSize;

	@Column(name = "trainerBreakDays")
	private Integer trainerBreakDays;

	@Column(name = "defaultLocation")
	private Integer defaultLocation;

	@Column(name = "defaultBuilding")
	private Integer defaultBuilding;

	@Column(name = "defaultNamePattern")
	private String defaultNamePattern;

	public Settings() {
		super();
	}

	public Settings(Integer id, String alias, Integer trainersPerPage, Integer batchLength,
			Integer reportIncomingCandidates, Integer reportOutgoingGrads, Integer minBatchSize, Integer maxBatchSize, Integer trainerBreakDays,
			Integer defaultLocation, Integer defaultBuilding, String defaultNamePattern) {
		super();
		this.id = id;
		this.alias = alias;
		this.trainersPerPage = trainersPerPage;

		this.batchLength = batchLength;
		this.reportIncomingCandidates = reportIncomingCandidates;
		this.reportOutgoingGrads = reportOutgoingGrads;
		this.minBatchSize = minBatchSize;
		this.maxBatchSize = maxBatchSize;
		this.trainerBreakDays = trainerBreakDays;
		this.defaultLocation = defaultLocation;
		this.defaultBuilding = defaultBuilding;
		this.defaultNamePattern = defaultNamePattern;
	}



	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public Integer getTrainersPerPage() {
		return trainersPerPage;
	}

	public void setTrainersPerPage(Integer trainersPerPage) {
		this.trainersPerPage = trainersPerPage;
	}

	public Integer getBatchLength() {
		return batchLength;
	}

	public void setBatchLength(Integer batchLength) {
		this.batchLength = batchLength;
	}

	public Integer getReportIncomingCandidates() {
		return reportIncomingCandidates;
	}

	public Integer getReportOutgoingGrads() {
		return reportOutgoingGrads;
	}

	public void setReportOutgoingGrads(Integer reportOutgoingGrads) {
		this.reportOutgoingGrads = reportOutgoingGrads;
	}

	public void setReportIncomingCandidates(Integer reportIncomingCandidates) {
		this.reportIncomingCandidates = reportIncomingCandidates;
	}

	public Integer getMinBatchSize() {
		return minBatchSize;
	}

	public void setMinBatchSize(Integer minBatchSize) {
		this.minBatchSize = minBatchSize;
	}

	public Integer getMaxBatchSize() {
		return maxBatchSize;
	}

	public void setMaxBatchSize(Integer maxBatchSize) {
		this.maxBatchSize = maxBatchSize;
	}

	public Integer getTrainerBreakDays() {
		return trainerBreakDays;
	}

	public void setTrainerBreakDays(Integer trainerBreakDays) {
		this.trainerBreakDays = trainerBreakDays;
	}

	public Integer getDefaultLocation() {
		return defaultLocation;
	}

	public void setDefaultLocation(Integer defaultLocation) {
		this.defaultLocation = defaultLocation;
	}

	public Integer getDefaultBuilding() {
		return defaultBuilding;
	}

	public void setDefaultBuilding(Integer defaultBuilding) {
		this.defaultBuilding = defaultBuilding;
	}

	public String getDefaultNamePattern() {
		return defaultNamePattern;
	}

	public void setDefaultNamePattern(String defaultNamePattern) {
		this.defaultNamePattern = defaultNamePattern;
	}

}
