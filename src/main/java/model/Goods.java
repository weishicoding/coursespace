package model;

import com.will.preloved.model.audit.DateAudit;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Table(name = "goods")
@Entity
@Getter
@Setter
public class Goods extends DateAudit {

    @Id
    @GeneratedValue
    private Long id;

    @NotBlank
    @Size(min = 1, max = 30)
    private String goodsName;

    @Column(columnDefinition = "text")
    private String goodsDescription;
}
